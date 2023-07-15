package structs

type CronJob struct {
	Id               int    `db:"id" json:"id" form:"id"`
	EntryId          int    `db:"entryid" json:"entryid" form:"entryid"`
	Active           bool   `db:"active" json:"active" form:"active"`
	Schedule         string `db:"schedule" json:"schedule" form:"schedule"`
	Bash             string `db:"bash" json:"bash" form:"bash"`
	Name             string `db:"name" json:"name" form:"name"`
	Group            string `db:"grp" json:"group" form:"group"`
	Desc             string `db:"description" json:"desc" form:"desc"`
	Severity         string `db:"severity" json:"severity" form:"severity"`
	FailsNeeded      int    `db:"failsneeded" json:"failsneeded" form:"failsneeded"`
	AlwaysNotify     bool   `db:"alwaysnotify" json:"alwaysnotify" form:"alwaysnotify"`
	RepeatNotifEvery int    `db:"repeatnotifevery" json:"repeatnotifevery" form:"repeatnotifevery"`
	NotifyGroup      string `db:"notifygroup" json:"notifygroup" form:"notifygroup"`
}

type CronJobLog struct {
	Id              int    `db:"id" json:"id" form:"id"`
	Success         bool   `db:"success" json:"success" form:"success"`
	Name            string `db:"name" json:"name" form:"name"`
	Timetaken       int64  `db:"timetaken" json:"timetaken" form:"timetaken"`
	Prettytimetaken string `db:"timetaken" json:"timetaken" form:"timetaken"`
	Output          string `db:"output" json:"output" form:"output"`
	Err             string `db:"err" json:"err" form:"err"`
	Created         string `db:"created" json:"created" form:"created"`
}

type NotifyGroup struct {
	Id             int    `db:"id" json:"id" form:"id"`
	Name           string `db:"name" json:"name" form:"name" binding:"required,min=1"`
	Gotifyurl      string `db:"gotifyurl" json:"gotifyurl" form:"gotifyurl"`
	Gotifykey      string `db:"gotifykey" json:"gotifykey" form:"gotifykey"`
	Emailaddresses string `db:"emailaddresses" json:"emailaddresses" form:"emailaddresses"`
	Webhookurl     string `db:"webhookurl" json:"webhookurl" form:"webhookurl"`
	Shouldemail    bool   `db:"shouldemail" json:"shouldemail" form:"shouldemail"`
	Shouldgotify   bool   `db:"shouldgotify" json:"shouldgotify" form:"shouldgotify"`
	Shouldwebhook  bool   `db:"shouldwebhook" json:"shouldwebhook" form:"shouldwebhook"`
}

// Used only by main:

type Config struct {
	Constring     string `json:"constring"`
	Historylength int    `json:"historylength"`
	Webuser       string `json:"webuser"`
	Webpass       string `json:"webpass"`
	CookieSecret  string `json:"cookiesecret"`
	Mailfrom      string `json:"mailfrom"`
	Mailpass      string `json:"mailpass"`
	Mailhost      string `json:"mailhost"`
	Mailport      string `json:"mailport"`
	Listenport    string `json:"listenport"`
	Host          string `json:"host"`
	Loglocation   string `json:"loglocation"`
}

type User struct {
	Name string `form:"name"`
	Pw   string `form:"pw"`
}

type Testbash struct {
	Bash string `form:"bash" json:"bash" xml:"bash"`
}

type Overview struct {
	Name    string `json:"name"`
	Group   string `json:"group"`
	Found   bool   `json:"found"`
	Success bool   `json:"success"`
	Err     string `json:"err"`
}
