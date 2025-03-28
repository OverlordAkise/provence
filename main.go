package main

import (
	//web and cron
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
	ginzap "github.com/gin-contrib/zap"
	"go.uber.org/zap"
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
	//webhooks
	"encoding/json"
	//rate limit
	"sync"
)

func AddCronjobStruct(cj structs.CronJob, c *cron.Cron, shouldSaveToDb bool) error {
	if cj.EntryId != 0 {
		logger.Infow("AddCronjob, replacing cronjob", "id", cj.EntryId, "name", cj.Name)
		c.Remove(cron.EntryID(cj.EntryId))
		CronJobNames.Delete(cj.Name)
	}
	eid, err := c.AddFunc(cj.Schedule, func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorw("recovered panic in cronjob", "recover", r)
			}
		}()
		ec := exec.Command("bash", "-c", cj.Bash) //.Output()
		var cmd bytes.Buffer
		var stderr bytes.Buffer
		ec.Stdout = &cmd
		ec.Stderr = &stderr
		starttime := time.Now()
		err := ec.Run()
		donetime := time.Now()
		taken := donetime.Sub(starttime)
		if err != nil {
			logger.Errorw("cronjob failed", "name", cj.Name, "err", err, "stdout", cmd.String(), "stderr", stderr.String(), "time", taken)
			AddCronjobLog(false, cj.Name, cmd.String(), fmt.Sprint(err)+": "+stderr.String(), taken)
			NotifyUsers(cj, fmt.Sprint(err)+": "+stderr.String(), true)
		} else {
			logger.Infow("cronjob succeeded", "name", cj.Name, "stdout", cmd.String(), "time", taken)
			AddCronjobLog(true, cj.Name, cmd.String(), "", taken)
			NotifyUsers(cj, cmd.String(), false)
		}
	})
	if err != nil {
		return err
	}
	id := int(eid)
	cj.EntryId = id
	CronJobNames.Store(cj.Name, cj)
	if shouldSaveToDb {
		err = Db.AddCronjob(cj)
		if err != nil {
			return err
		}
	}
	logger.Infow("cronjob added", "name", cj.Name, "id", cj.EntryId)
	return nil
}

func DeleteCronjob(cj structs.CronJob, c *cron.Cron) error {
	err := Db.DeleteCronjob(cj)
	if err != nil {
		return err
	}
	name := cj.Name
	ieid, eidExists := CronJobNames.Load(name)
	eid := ieid.(structs.CronJob)
	if !eidExists {
		return fmt.Errorf("Cronjob for deletion not found in CronJobNames! Impossible to delete!")
	}
	c.Remove(cron.EntryID(eid.EntryId))
	CronJobNames.Delete(name)
	CronJobLogLast.Delete(name)
	logger.Infow("cronjob deleted", "name", name, "id", eid.EntryId)
	return nil
}

func AddCronjobLog(success bool, name, output, errStr string, timeTaken time.Duration) {
	cjl := structs.CronJobLog{}
	cjl.Success = success
	cjl.Name = name
	cjl.Timetaken = int64(timeTaken) //time.Duration is just a int64
	cjl.Output = output
	cjl.Err = errStr
	err := Db.AddCronjobLog(cjl)
	if err != nil {
		logger.Errorw("add cronjoblog error", "name", name, "err", err)
	}
	CronJobLogLast.Store(name, cjl)
}

func GetCronjobLog(name string) {
	cjl, err := Db.GetLastLog(name)
	if err != nil {
		logger.Errorw("get cronjoblog error", "name", name, "err", err)
		return
	}
	CronJobLogLast.Store(name, cjl)
}

func NotifyUsers(cjo structs.CronJob, errstr string, isError bool) {
	//If notifygroup changed we get the correct cache here
	var cj structs.CronJob
	icj, cjExists := CronJobNames.Load(cjo.Name)
	if !cjExists {
		logger.Warnw("couldnt get cronjob from CronJobNames", "name", cjo.Name)
		cj = cjo
	} else {
		cj = icj.(structs.CronJob)
	}
	ng, err := Db.GetNotifyGroup(cj.NotifyGroup)
	if err != nil {
		logger.Errorw("couldnt get notifygroup from db", "name", cj.Name, "notifygroup", cj.NotifyGroup, "err", err)
		return
	}

	if ng.Name == "" {
		logger.Errorw("no notifygroup found for cronjob", "name", cj.Name, "notifygroup", cj.NotifyGroup)
		return
	}

	tag := "[error]"
	infoMsg := ""
	shouldNotify := false
	icjfs, cerr := CronJobFails.Load(cj.Name)
	var cjfs int = 0
	if !cerr {
		cjfs = icjfs.(int)
	}

	if !isError {
		tag = "[info]"
		if cjfs > 0 {
			tag = "[info] Recovered"
			shouldNotify = true
		}
		if cj.AlwaysNotify {
			shouldNotify = true
		}
		CronJobFails.Store(cj.Name, 0)
	} else {
		CronJobFails.Store(cj.Name, cjfs+1)
		cjfs += 1
		if cj.FailsNeeded <= cjfs {
			if cjfs == 1 || cjfs%cj.RepeatNotifEvery == 0 {
				shouldNotify = true
			}
		}
	}

	if !shouldNotify {
		logger.Infow("not notifying", "name", cj.Name, "failcount", cjfs)
		return
	}

	logger.Infow("sending notifications", "name", cj.Name, "notifygroup", ng.Name, "shouldemail", ng.Shouldemail, "shouldgotify", ng.Shouldgotify, "shouldwebhook", ng.Shouldwebhook)

	if ng.Shouldemail {
		auth := smtp.PlainAuth("", config.Mailfrom, config.Mailpass, config.Mailhost)
		err := smtp.SendMail(config.Mailhost+":"+config.Mailport, auth, config.Mailfrom, strings.Split(ng.Emailaddresses, ";"), []byte("Subject: [provence]"+tag+" "+cj.Name+"\n\n"+infoMsg+errstr))
		if err != nil {
			logger.Errorw("error during email notification", "name", cj.Name, "notifygroup", ng.Name, "err", err)
		}
	}

	if ng.Shouldgotify {
		_, err := http.PostForm(ng.Gotifyurl+"message?token="+ng.Gotifykey,
			url.Values{"message": {errstr}, "title": {cj.Name}, "priority": {"9"}})
		if err != nil {
			logger.Errorw("error during gotify notification", "name", cj.Name, "notifygroup", ng.Name, "err", err)
		}
	}

	if ng.Shouldwebhook {
		data := map[string]interface{}{
			"content": "[provence]" + tag + " " + cj.Name + "\n\n" + infoMsg + errstr,
		}
		jsonData, err := json.Marshal(data)
		if err != nil {
			logger.Errorw("error during webhook notification", "name", cj.Name, "notifygroup", ng.Name, "err", err)
			return
		}
		req, err := http.NewRequest("POST", ng.Webhookurl, bytes.NewReader(jsonData))
		if err != nil {
			logger.Errorw("error during webhook notification", "name", cj.Name, "notifygroup", ng.Name, "err", err)
			return
		}
		req.Header.Add("Content-Type", "application/json")
		_, err = httpclient.Do(req)
		if err != nil {
			logger.Errorw("error during webhook notification", "name", cj.Name, "notifygroup", ng.Name, "err", err)
		}
	}
}

// Logging
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		t := time.Now()
		logger.Infow("webrequest",
			"url", c.Request.URL.String(),
			"method", c.Request.Method,
			"ret", c.Writer.Status(),
			"ip", c.ClientIP(),
			"duration", t.Sub(start),
			"rsize", c.Writer.Size(),

			//If you use "go.opentelemetry.io/otel":
			//"trace_id",tr.SpanFromContext(c.Request.Context()).SpanContext().TraceID().String(),
		)
	}
}

var logger *zap.SugaredLogger

// Caches
var CronJobLogLast sync.Map // = make(map[string]structs.CronJobLog)
var CronJobNames sync.Map   // = make(map[string]structs.CronJob)
var CronJobFails sync.Map   // = make(map[string]int)
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
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{
		config.Loglocation,
	}
	flogger, err := cfg.Build()
	logger = flogger.Sugar()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	//CronJobs
	cr := cron.New()
	cronjobs, err := Db.GetAllCronjobs()
	if err != nil {
		panic(err)
	}
	for _, cj := range cronjobs {
		if cj.Active {
			AddCronjobStruct(cj, cr, false)
		} else {
			CronJobNames.Store(cj.Name, cj)
		}
		GetCronjobLog(cj.Name)
	}
	cr.Start()
	logger.Info("started cron")

	//Webserver
	gin.SetMode(gin.ReleaseMode)
	app := gin.New()
	app.Use(ginzap.RecoveryWithZap(flogger, true))
	app.Use(RequestLogger())
	gin.DisableConsoleColor()
	//app.LoadHTMLGlob("templates/*")
	templ := template.Must(template.ParseFS(templates, "templates/*"))
	app.SetHTMLTemplate(templ)

	store := cookie.NewStore([]byte(config.CookieSecret))
	app.Use(sessions.Sessions("provencesession", store))

	//app.Static("/assets", "./web_res")
	assetsFS, err := fs.Sub(webres, "web_res")
	if err != nil {
		panic(err)
	}
	app.StaticFS("/assets", http.FS(assetsFS))

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

	var ratemap sync.Map
	var ratereset int64 = 0
	app.POST("/login", func(c *gin.Context) {
		// poor-mans ratelimit, 1req/s, clear every 1min
		ip := c.ClientIP()
		curtime := time.Now().Unix()
		t, found := ratemap.Load(ip)
		if found {
			if t.(int64) > curtime-1 {
				c.String(429, "too many requests")
				return
			}
		}
		ratemap.Store(ip, curtime)
		if ratereset < curtime-60 {
			ratereset = curtime
			ratemap.Range(func(key, value interface{}) bool {
				ratemap.Delete(key)
				return true
			})
		}
		//login logic
		u := new(structs.User)
		if err := c.ShouldBind(u); err != nil {
			logger.Errorw("/login bind error", "err", err)
			c.Redirect(302, config.Host+"login")
			return
		}
		sess := sessions.Default(c)
		if u.Name != config.Webuser || u.Pw != config.Webpass {
			logger.Errorw("wrong login", "name", u.Name, "pw", u.Pw)
			c.Redirect(302, config.Host+"login")
			return
		}
		sess.Set("name", u.Name)
		sess.Options(sessions.Options{
			MaxAge: 3600 * 12, // 12hrs
		})
		sess.Save()
		c.Redirect(302, config.Host+"home")
	})

	app.GET("/logout", func(c *gin.Context) {
		sess := sessions.Default(c)
		sess.Clear()
		sess.Save()
		c.Redirect(302, config.Host+"home")
	})

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
		CronJobNames.Range(func(key, icj any) bool {
			cj := icj.(structs.CronJob)
			ill, exists := CronJobLogLast.Load(cj.Name)
			a := structs.Overview{}
			a.Name = cj.Name
			a.Group = cj.Group
			a.Err = ""
			a.Found = false
			a.Success = false
			if exists {
				ll := ill.(structs.CronJobLog)
				a.Found = true
				a.Success = ll.Success
				a.Err = ll.Err
			}
			overview[cj.Group] = append(overview[cj.Group], a)
			return true
		})
		c.HTML(200, "home", gin.H{
			"Title":    "Provence | Home",
			"Overview": overview,
		})
	})

	app.GET("/jobs", func(c *gin.Context) {
		cjs, err := Db.GetAllCronjobs()
		if err != nil {
			logger.Errorw("/jobs db error", "func", "GetAllCronjobs", "err", err)
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
			logger.Errorw("/history db error", "func", "GetLastLogs", "name", aname, "err", err)
			c.String(500, err.Error())
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
			logger.Errorw("/notifygroups db error", "func", "GetAllNotifygroups", "err", err)
			c.String(500, err.Error())
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
			logger.Errorw("/editjob db error", "func", "GetAllNotifygroups", "err", err)
			c.String(500, err.Error())
			return
		}
		cj, err := Db.GetCronjob(aname)
		if err != nil {
			logger.Errorw("/editjob db error", "func", "GetCronjob", "name", aname, "err", err)
			c.String(500, err.Error())
			return
		}
		c.HTML(200, "editjob", gin.H{
			"Title":        "Provence | Edit Job " + aname,
			"Cronjob":      cj,
			"NotifyGroups": ngs, //for dropdown selection
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
		ngs, err := Db.GetAllNotifygroups()
		if err != nil {
			logger.Errorw("/addjob db error", "func", "GetAllNotifygroups", "err", err)
			c.String(500, err.Error())
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
		if err := c.BindJSON(ng); err != nil {
			return
		}
		err := Db.AddNotifygroup(*ng)
		if err != nil {
			logger.Errorw("/notifygroup db error", "func", "AddNotifygroup", "name", ng.Name, "err", err)
			c.String(500, err.Error())
			return
		}
		c.String(200, "OK")
	})
	app.POST("/job", func(c *gin.Context) {
		cj := new(structs.CronJob)
		if err := c.BindJSON(cj); err != nil {
			return
		}
		err := AddCronjobStruct(*cj, cr, true)
		if err != nil {
			logger.Errorw("/job db error", "func", "AddCronjobStruct", "name", cj.Name, "err", err)
			c.String(500, err.Error())
			return
		}
		c.String(200, "OK")
	})

	app.POST("/deletejob", func(c *gin.Context) {
		cj := new(structs.CronJob)
		if err := c.BindJSON(cj); err != nil {
			return
		}
		err := DeleteCronjob(*cj, cr)
		if err != nil {
			logger.Errorw("/deletejob db error", "func", "DeleteCronjob", "name", cj.Name, "err", err)
			c.String(500, err.Error())
			return
		}
		c.String(200, "OK")
	})

	app.POST("/deletenotifygroup", func(c *gin.Context) {
		ng := new(structs.NotifyGroup)
		if err := c.BindJSON(ng); err != nil {
			return
		}
		err := Db.DeleteNotifygroup(*ng)
		if err != nil {
			logger.Errorw("/deletenotifygroup db error", "func", "DeleteNotifygroup", "name", ng.Name, "err", err)
			c.String(500, err.Error())
			return
		}
		c.String(200, "OK")
	})

	app.POST("/testbash", func(c *gin.Context) {
		tj := new(structs.Testbash)
		if err := c.BindJSON(tj); err != nil {
			return
		}
		logger.Infow("testing bash", "bash", tj.Bash)
		ec := exec.Command("bash", "-c", tj.Bash) //.Output()
		var cmd bytes.Buffer
		var stderr bytes.Buffer
		ec.Stdout = &cmd
		ec.Stderr = &stderr
		err := ec.Run()
		if err != nil {
			logger.Errorw("testbash failed", "err", err, "stdout", cmd.String(), "stderr", stderr.String())
			c.String(500, stderr.String())
		} else {
			logger.Infow("testbash success", "stdout", cmd.String(), "stderr", stderr.String())
			c.String(200, cmd.String())
		}
	})

	//Status Active / Inactive
	app.POST("/toggleactive", func(c *gin.Context) {
		tempcj := new(structs.CronJob)
		if err := c.BindJSON(tempcj); err != nil {
			return
		}
		//logic to let cronjob run again
		cj, err := Db.GetCronjob(tempcj.Name)
		if err != nil {
			logger.Errorw("/toggleactive db error", "func", "GetCronjob", "name", tempcj.Name, "err", err)
			c.String(500, err.Error())
			return
		}
		if !cj.Active {
			AddCronjobStruct(cj, cr, false)
			GetCronjobLog(cj.Name)
			err = Db.SetCronjobStatus(cj, true)
			if err != nil {
				logger.Errorw("/toggleactive db error", "func", "SetCronjobStatus", "name", tempcj.Name, "err", err)
				c.String(500, err.Error())
				return
			}
		} else {
			icj, exists := CronJobNames.Load(cj.Name)
			if !exists {
				logger.Errorw("/toggleactive with non-existing name error", "name", cj.Name)
				c.String(500, "ERROR: Name doesnt exist!")
				return
			}
			loadedCJ := icj.(structs.CronJob)
			cr.Remove(cron.EntryID(loadedCJ.EntryId))
			err = Db.SetCronjobStatus(loadedCJ, false)
			if err != nil {
				logger.Errorw("/toggleactive db error", "func", "SetCronjobStatus", "name", cj.Name, "err", err)
				c.String(500, err.Error())
				return
			}
		}
		c.String(200, "OK")
	})

	donetime := time.Now()
	logger.Infow("provence started", "time", donetime.Sub(starttime), "port", config.Listenport, "host", config.Host)
	err = app.Run(":" + config.Listenport)
	if err != nil {
		logger.Errorw("gin.Run error", "err", err)
	}
}
