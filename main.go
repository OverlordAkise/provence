package main

import (
	"bytes"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
	Db "luctus.at/provence/database"
	structs "luctus.at/provence/structs"
	"os/exec"
	"strings"
	"time"
	//Logging
	"log"
	"os"
	//Config file
	"io/ioutil"
	"sigs.k8s.io/yaml"
	//Notify gotify
	"net/http"
	"net/smtp"
	"net/url"
	//gin embed.FS support
	"embed"
	"html/template"
	"io/fs"
	//oidc support
	"context"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	//webhooks
	"encoding/json"
)

var (
	callbackPath = "auth/callback"
)

func WrapF(f http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		newCtx := context.WithValue(c.Request.Context(), "session", c)
		f(c.Writer, c.Request.WithContext(newCtx))
	}
}

func AddCronjobStruct(cj structs.CronJob, c *cron.Cron, shouldSaveToDb bool) error {
	if cj.EntryId != 0 {
		LogInfo("AddCronjobStruct() // exists,replacing")
		c.Remove(cron.EntryID(cj.EntryId))
		delete(CronJobNames, cj.Name)
	}
	eid, err := c.AddFunc(cj.Schedule, func() {
		defer func() {
			if r := recover(); r != nil {
				LogError("Recovered panic in CronFunc!:", r)
			}
		}()
		ec := exec.Command("bash", "-c", cj.Bash) //.Output()
		var cmd bytes.Buffer
		var stderr bytes.Buffer
		ec.Stdout = &cmd
		ec.Stderr = &stderr
		err := ec.Run()
		if err != nil {
			LogError("CronJob failed exec: ", cj.Name, " // ", fmt.Sprint(err)+": "+stderr.String())
			AddCronjobLog(false, cj.Name, cmd.String(), fmt.Sprint(err)+": "+stderr.String())
			NotifyUsers(cj, fmt.Sprint(err)+": "+stderr.String(), true)
		} else {
			LogInfo("CronJob succeeded exec: ", cj.Name)
			AddCronjobLog(true, cj.Name, cmd.String(), "")
			NotifyUsers(cj, cmd.String(), false)
		}
	})
	if err != nil {
		LogError("cron.AddFunc(", cj.Schedule, ",", cj.Name, ") // err")
		return err
	}
	id := int(eid)
	cj.EntryId = id
	CronJobNames[cj.Name] = cj
	if shouldSaveToDb {
		err = Db.AddCronjob(cj)
		if err != nil {
			LogError("Db.AddCronjob(", cj.Name, ") // ", err)
			return err
		}
	}
	LogInfo("AddCronjobStruct() // ", cj.Name)
	return nil
}

func DeleteCronjob(dj structs.DeleteStruct, c *cron.Cron) error {
	err := Db.DeleteCronjob(dj)
	if err != nil {
		LogError("Db.DeleteCronjob(", dj.Name, ") // ", err)
		return err
	}
	eid, eidExists := CronJobNames[dj.Name]
	if !eidExists {
		LogError("DeleteCronjob() // ", dj.Name, " cronjob doesn't exist in Names map!")
		return nil
	}
	c.Remove(cron.EntryID(eid.EntryId))
	delete(CronJobNames, dj.Name)
	delete(CronJobLogLast, dj.Name)
	LogInfo("DeleteCronjob() // ", dj.Name)
	return nil
}

func AddCronjobLog(success bool, name, output, errStr string) {
	cjl := structs.CronJobLog{}
	cjl.Success = success
	cjl.Name = name
	cjl.Output = output
	cjl.Err = errStr
	err := Db.AddCronjobLog(cjl)
	if err != nil {
		LogError("Db.AddCronjobLog() // ", name, " ", err)
	}
	CronJobLogLast[name] = cjl
}

func GetCronjobLog(name string) {
	cjl, err := Db.GetLastLog(name)
	if err != nil {
		LogError("GetCronjobLog() // No logs found for:", name)
		return
	}
	CronJobLogLast[name] = cjl
}

func NotifyUsers(cjo structs.CronJob, errstr string, isError bool) {
	//If notifygroup changed we get the correct cache here
	cj, cjExists := CronJobNames[cjo.Name]
	if !cjExists {
		LogError("NotifyUsers() CronJobNames[Name] // Couldn't cjo in cache, using old!")
		cj = cjo
	}
	ng, dbError := Db.GetNotifyGroup(cj.NotifyGroup)
	if dbError != nil {
		LogError("Db.GetNotifyGroup(", cj.Name, ",", isError, ") // ", dbError)
		return
	}

	tag := "[error]"
	infoMsg := ""
	shouldNotify := false

	if !isError {
		tag = "[info]"
		if CronJobFails[cj.Name] > 0 {
			tag = "[info] Recovered"
			shouldNotify = true
		}
		if cj.AlwaysNotify {
			shouldNotify = true
		}
		CronJobFails[cj.Name] = 0
	} else {
		CronJobFails[cj.Name] += 1
		if cj.FailsNeeded <= CronJobFails[cj.Name] {
			if CronJobFails[cj.Name] == 1 || CronJobFails[cj.Name]%cj.RepeatNotifEvery == 0 {
				shouldNotify = true
			}
		}
	}

	if !shouldNotify {
		LogInfo("Not notifying: ", cj.Name, CronJobFails[cj.Name])
		return
	}

	if ng.Name == "" {
		LogError("ERROR: NO NOTIFYGROUP FOUND ON CRONJOB!:")
		LogError(cj)
		return
	}
	if ng.Shouldemail {
		LogInfo("Notifying via email")
		auth := smtp.PlainAuth("", config.Mailfrom, config.Mailpass, config.Mailhost)
		err := smtp.SendMail(config.Mailhost+":"+config.Mailport, auth, config.Mailfrom, strings.Split(ng.Emailaddresses, ";"), []byte("Subject: [provence]"+tag+" "+cj.Name+"\n\n"+infoMsg+errstr))
		if err != nil {
			LogError("ERROR DURING EMAIL NOTIF:")
			LogError(err)
		}
	}
	if ng.Shouldgotify {
		LogInfo("Notifying via gotify")
		http.PostForm(ng.Gotifyurl+"message?token="+ng.Gotifykey,
			url.Values{"message": {errstr}, "title": {cj.Name}, "priority": {"9"}})
	}
	if ng.Shouldwebhook {
		LogInfo("Notifying via webhook")
		data := map[string]interface{}{
			"content": "[provence]" + tag + " " + cj.Name + "\n\n" + infoMsg + errstr,
		}
		jsonData, err := json.Marshal(data)
		if err != nil {
			LogError("ERROR DURING Webhook json.Marshal")
			LogError(err)
			return
		}
		req, err := http.NewRequest("POST", ng.Webhookurl, bytes.NewReader(jsonData))
		if err != nil {
			LogError("ERROR DURING http.NewRequest CREATION!")
			LogError(err)
			return
		}
		req.Header.Add("Content-Type", "application/json")
		_, err = httpclient.Do(req)
		if err != nil {
			LogError("ERROR DURING httpclient.Do")
			LogError(err)
		}
	}

}

// Logging
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		t := time.Now()
		LogReq(c.Request.URL, " | ", c.Writer.Status(), " | ", c.ClientIP(), " | ", t.Sub(start), " | size ", c.Writer.Size())
	}
}

func LogError(v ...any) {
	v = append([]interface{}{"[error] "}, v...)
	Logger.Println(v...)
}

func LogInfo(v ...any) {
	v = append([]interface{}{"[info ] "}, v...)
	Logger.Println(v...)
}

func LogReq(v ...any) {
	v = append([]interface{}{"[req  ] "}, v...)
	Logger.Println(v...)
}

var Logger *log.Logger

// Caches
var CronJobLogLast = make(map[string]structs.CronJobLog)
var CronJobNames = make(map[string]structs.CronJob)
var CronJobFails = make(map[string]int)
var config structs.Config
var httpclient = http.Client{}

//go:embed all:templates/*
var templates embed.FS

//go:embed all:web_res/*
var webres embed.FS

func main() {
	starttime := time.Now()
	//read config
	configfile, err := ioutil.ReadFile("./config.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(configfile, &config)
	if err != nil {
		panic(err)
	}

	//Database
	Db.Init(config.Constring)

	//Logger
	Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lmsgprefix|log.Lshortfile)
	fmt.Println("Logger setup done!")

	//CronJobs
	cr := cron.New()
	cronjobs, err := Db.GetAllCronjobs()
	if err != nil {
		panic(err)
	}
	for _, cj := range cronjobs {
		LogInfo("AddCronjobStruct() init // ", cj.Name)
		if cj.Active {
			AddCronjobStruct(cj, cr, false)
		} else {
			CronJobNames[cj.Name] = cj
		}
		GetCronjobLog(cj.Name)
	}
	cr.Start()

	//oidc
	state := func() string {
		a := uuid.New().String()
		//fmt.Println("New UUID:",a)
		return a
	}
	var provider rp.RelyingParty
	if config.UseOidc {
		redirectURI := config.Host + callbackPath
		scopes := strings.Split("email openid", " ")
		key := []byte(config.OidcCookieKey)
		cookieHandler := httphelper.NewCookieHandler(key, key, httphelper.WithUnsecure())
		options := []rp.Option{
			rp.WithCookieHandler(cookieHandler),
			rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		}
		if config.ClientSecret == "" {
			options = append(options, rp.WithPKCE(cookieHandler))
		}
		var err error
		provider, err = rp.NewRelyingPartyOIDC(config.Issuer, config.ClientID, config.ClientSecret, redirectURI, scopes, options...)
		if err != nil {
			panic("error creating keycloak provider " + err.Error())
		}
	}

	//Webserver
	gin.SetMode(gin.ReleaseMode)
	app := gin.New()
	app.Use(gin.Recovery())
	app.Use(RequestLogger())
	gin.DisableConsoleColor()
	//app.LoadHTMLGlob("templates/*")
	templ := template.Must(template.ParseFS(templates, "templates/*"))
	app.SetHTMLTemplate(templ)

	store := cookie.NewStore([]byte(config.OidcCookieKey))
	app.Use(sessions.Sessions("provencesession", store))

	//app.Static("/assets", "./web_res")
	assetsFS, err := fs.Sub(webres, "web_res")
	if err != nil {
		panic(err)
	}
	app.StaticFS("/assets", http.FS(assetsFS))

	if config.UseOidc {
		app.Use(func(c *gin.Context) {
			s := sessions.Default(c)
			name := s.Get("name")
			//fmt.Println(c.FullPath(),"Name:",name)
			if c.FullPath() == "/"+callbackPath {
				return
			}
			if c.FullPath() == "/login" {
				return
			}

			if name == nil {
				c.Redirect(307, config.Host+"login")
				c.Abort()
			}
		})
	} else {
		app.Use(func(c *gin.Context) {
			if c.FullPath() == "/login" || c.FullPath() == "/favicon.ico" {
				c.Next()
				return
			}
			session := sessions.Default(c)
			if session.Get("name") == nil || session.Get("name") == "" {
				c.Redirect(307, config.Host+"login")
				return
			}
			c.Next()
		})
	}

	if config.UseOidc {
		app.GET("/login", gin.WrapF(rp.AuthURLHandler(state, provider)))
		app.GET("/logout", func(c *gin.Context) {
			s := sessions.Default(c)
			idt := s.Get("idtoken").(string)
			_, err := rp.EndSession(provider, idt, config.Host+"loggedout", "")
			if err != nil {
				c.String(500, "ERROR during oidc logout!")
				fmt.Println(err)
				return
			}
			s.Clear()
			err = s.Save()
			if err != nil {
				c.String(500, "ERROR during session save!")
				fmt.Println(err)
				return
			}
			c.Redirect(301, config.Host+"loggedout")
		})
		setSessionFunc := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {
			c := r.Context().Value("session").(*gin.Context)
			s := sessions.Default(c)
			s.Set("name", info.UserInfoProfile.PreferredUsername)
			s.Set("idtoken", tokens.IDToken)
			//fmt.Println("UserInfo:",info)
			s.Save()
			http.Redirect(w, r, config.Host+"home", 301)
		}
		app.GET(callbackPath, WrapF(rp.CodeExchangeHandler(rp.UserinfoCallback(setSessionFunc), provider)))
	} else {
		app.GET("/login", func(c *gin.Context) {
			session := sessions.Default(c)
			if session.Get("name") != nil {
				c.Redirect(302, config.Host+"home")
				return
			}
			c.HTML(200, "login", gin.H{
				"Title": "Provence | Login",
			})
		})
		app.POST("/login", func(c *gin.Context) {
			u := new(structs.User)
			if err := c.ShouldBind(u); err != nil {
				LogError("login error (c.ShouldBind) // ", err)
				c.Redirect(302, config.Host+"login")
				return
			}
			sess := sessions.Default(c)
			if u.Name != config.Webuser || u.Pw != config.Webpass {
				LogError("login wrong password (", u.Name, ",", u.Pw, ")")
				c.Redirect(302, config.Host+"login")
				return
			}
			sess.Set("name", u.Name)
			sess.Save()
			c.Redirect(302, config.Host+"home")
		})

		app.GET("/logout", func(c *gin.Context) {
			sess := sessions.Default(c)
			sess.Clear()
			sess.Save()
			c.Redirect(302, config.Host+"home")
		})
	}

	// Routes
	app.GET("/", func(c *gin.Context) {
		c.Redirect(302, config.Host+"home")
	})

	app.GET("/status", func(c *gin.Context) {
		c.HTML(200, "status", gin.H{
			"Title": "Provence | Status",
		})
	})

	app.GET("/home", func(c *gin.Context) {
		overview := make(map[string][]structs.Overview)
		//only show active cronjobs, so we use CronJobNames here
		for _, cj := range CronJobNames {
			ll, exists := CronJobLogLast[cj.Name]
			a := structs.Overview{}
			a.Name = cj.Name
			a.Group = cj.Group
			a.Err = ""
			a.Found = false
			a.Success = false
			if exists {
				a.Found = true
				a.Success = ll.Success
				a.Err = ll.Err
			}
			overview[cj.Group] = append(overview[cj.Group], a)
		}
		c.HTML(200, "home", gin.H{
			"Title":    "Provence | Home",
			"Overview": overview,
		})
	})

	app.GET("/jobs", func(c *gin.Context) {
		cjs, err := Db.GetAllCronjobs()
		if err != nil {
			LogError("/home Db.GetAllCronjobs()// ", err)
			c.String(500, err.Error())
			return
		}
		c.HTML(200, "jobs", gin.H{
			"Title":    "Provence | Jobs",
			"CronJobs": cjs,
		})
	})

	app.GET("/history", func(c *gin.Context) {
		aname := c.DefaultQuery("name", "")
		cjls, err := Db.GetLastLogs(aname, config.Historylength)
		if err != nil {
			LogError("Db.GetLastLogs(", aname, ") // ", err)
			c.String(500, "ERROR DURING GETLASTLOGS!")
			return
		}
		c.HTML(200, "history", gin.H{
			"Title":   "Provence | History",
			"Name":    aname,
			"History": cjls,
		})
	})

	app.GET("/notifygroups", func(c *gin.Context) {
		ngs, err := Db.GetAllNotifygroups()
		if err != nil {
			LogError("Db.GetAllNotifygroups() // ", err)
			c.String(500, "ERROR DURING GETALLNOTIFYGROUPS!")
			return
		}
		c.HTML(200, "notifygroups", gin.H{
			"Title":        "Provence | NotifyGroups",
			"NotifyGroups": ngs,
		})
	})

	app.GET("/editjob", func(c *gin.Context) {
		aname := c.DefaultQuery("name", "")
		ngs, err := Db.GetAllNotifygroups()
		if err != nil {
			LogError("Db.GetAllNotifygroups() // ", err)
			c.String(500, "ERROR DURING GETALLNOTIFYGROUPS!")
			return
		}
		c.HTML(200, "editjob", gin.H{
			"Title":        "Provence | Edit Job " + aname,
			"Cronjob":      CronJobNames[aname], //null aka. new job if empty
			"NotifyGroups": ngs,                 //for dropdown selection
		})
	})

	app.GET("/editnotifygroup", func(c *gin.Context) {
		aname := c.DefaultQuery("name", "")
		ng, err := Db.GetNotifyGroup(aname)
		if err != nil {
			c.HTML(200, "editnotifygroup", gin.H{
				"Title": "Provence | New Notifygroup " + aname,
			})
			return
		}
		c.HTML(200, "editnotifygroup", gin.H{
			"Title":       "Provence | Edit Notifygroup " + aname,
			"NotifyGroup": ng,
		})
	})

	app.GET("/addjob", func(c *gin.Context) {
		ngs, ngerr := Db.GetAllNotifygroups()
		if ngerr != nil {
			LogError("Db.GetAllNotifygroups() // ", err)
			c.String(500, "ERROR DURING GETALLNOTIFYGROUPS!")
			return
		}
		c.HTML(200, "editjob", gin.H{
			"Title":        "Provence | Addjob",
			"NotifyGroups": ngs, //for dropdown selection
		})
	})
	app.GET("/addnotifygroup", func(c *gin.Context) {
		c.HTML(200, "editnotifygroup", gin.H{
			"Title": "Provence | Addnotifygroup",
		})
	})

	// API
	app.POST("/notifygroup", func(c *gin.Context) {
		ng := new(structs.NotifyGroup)
		if err := c.ShouldBind(ng); err != nil {
			LogError("POST /notifygroup bind error // ", err)
			c.String(500, err.Error())
			return
		}
		err := Db.AddNotifygroup(*ng)
		if err != nil {
			LogError("Db.AddNotifygroup(", ng.Name, ") // ", err)
			c.String(500, err.Error())
			return
		}
		c.Redirect(302, config.Host+"notifygroups")
	})
	app.POST("/job", func(c *gin.Context) {
		cj := new(structs.CronJob)
		if err := c.ShouldBind(cj); err != nil {
			LogError("POST /job bind error // ", err)
			c.String(500, err.Error())
			return
		}
		err := AddCronjobStruct(*cj, cr, true)
		if err != nil {
			LogError("Db.AddNotifygroup(", cj.Name, ") // ", err)
			c.String(500, err.Error())
			return
		}
		c.Redirect(302, config.Host+"jobs")
	})

	app.POST("/deletejob", func(c *gin.Context) {
		dj := new(structs.DeleteStruct)
		if err := c.ShouldBind(dj); err != nil {
			LogError("POST /deletejob bind error // ", err)
			c.String(500, err.Error())
			return
		}
		err := DeleteCronjob(*dj, cr)
		if err != nil {
			LogError("Db.AddNotifygroup(", dj.Name, ") // ", err)
			c.String(500, err.Error())
			return
		}
		c.String(200, "OK")
	})

	app.POST("/deletenotifygroup", func(c *gin.Context) {
		dn := new(structs.DeleteStruct)
		if err := c.ShouldBind(dn); err != nil {
			LogError("POST /deletenotifygroup bind error // ", err)
			c.String(500, err.Error())
			return
		}
		err := Db.DeleteNotifygroup(*dn)
		if err != nil {
			LogError("Db.AddNotifygroup(", dn.Name, ") // ", err)
			c.String(500, err.Error())
			return
		}
		c.String(200, "OK")
	})

	app.POST("/testbash", func(c *gin.Context) {
		tj := new(structs.Testbash)
		if err := c.ShouldBind(tj); err != nil {
			c.String(500, "Binding failed")
			return
		}
		LogInfo("/testbash before test // ", strings.ReplaceAll(tj.Bash, "\n", "\\n"))
		ec := exec.Command("bash", "-c", tj.Bash) //.Output()
		var cmd bytes.Buffer
		var stderr bytes.Buffer
		ec.Stdout = &cmd
		ec.Stderr = &stderr
		err := ec.Run()
		if err != nil {
			strerr := fmt.Sprint(err) + ": " + stderr.String()
			LogError("/testbash failed // ", strings.ReplaceAll(strerr, "\n", "\\n"))
			c.String(500, strerr)
		} else {
			LogInfo("/testbash succeeded // ", strings.ReplaceAll(cmd.String(), "\n", "\\n"))
			c.String(200, cmd.String())
		}
	})

	//Status Active / Inactive
	app.GET("/setactive", func(c *gin.Context) {
		aname := c.DefaultQuery("name", "")
		//logic to let cronjob run again
		cj, err := Db.GetCronjob(aname)
		if err != nil {
			LogError("Db.GetCronjob(", aname, ") // ", err)
			c.String(500, err.Error())
			return
		}
		AddCronjobStruct(cj, cr, false)
		GetCronjobLog(cj.Name)
		//save to db that its active again
		err = Db.SetCronjobActive(structs.DeleteStruct{aname})
		if err != nil {
			LogError("Db.SetCronjobActive(", aname, ") // ", err)
			c.String(500, err.Error())
			return
		}
		c.Redirect(302, config.Host+"jobs")
	})
	app.GET("/setinactive", func(c *gin.Context) {
		aname := c.DefaultQuery("name", "")
		cj, exists := CronJobNames[aname]
		if !exists {
			LogError("/setinactive with non-existing name: ", aname)
			c.String(500, "ERROR: Name doesnt exist!")
			return
		}
		//logic to set cronjob inactive
		cr.Remove(cron.EntryID(cj.EntryId))
		//delete(CronJobNames, cj.Name)
		//save to db that its active again
		err := Db.SetCronjobInactive(structs.DeleteStruct{aname})
		if err != nil {
			LogError("Db.SetCronjobInactive(", aname, ") // ", err)
			c.String(500, err.Error())
			return
		}
		c.Redirect(302, config.Host+"jobs")
	})

	donetime := time.Now()
	LogInfo("Startup finished, time taken:", donetime.Sub(starttime))
	LogInfo("Port:", config.Listenport, "Host:", config.Host)
	LogInfo("Now Listening...")
	LogError(app.Run(":" + config.Listenport))
}
