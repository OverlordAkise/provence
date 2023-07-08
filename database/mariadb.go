package database

import (
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	structs "luctus.at/provence/structs"
)

var db *sqlx.DB

func Init(conString string) {
	var err error
	db, err = sqlx.Open("mysql", conString)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	db.MustExec("CREATE TABLE IF NOT EXISTS cronjob(id SERIAL, active BOOL, schedule VARCHAR(16), bash LONGTEXT, name VARCHAR(255) UNIQUE, grp VARCHAR(255), description TEXT, severity VARCHAR(255), failsneeded INT, repeatnotifevery INT, alwaysnotify BOOL, notifygroup VARCHAR(255), created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);")
	db.MustExec("CREATE TABLE IF NOT EXISTS notifygroup(id SERIAL, name VARCHAR(255) UNIQUE, gotifyurl VARCHAR(255), gotifykey VARCHAR(100), emailaddresses TEXT, webhookurl TEXT, shouldemail BOOL, shouldgotify BOOL, shouldwebhook BOOL);")
	db.MustExec("CREATE TABLE IF NOT EXISTS cronjoblog(id SERIAL, created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, success BOOL, name VARCHAR(255), output LONGTEXT, err LONGTEXT);")
	fmt.Println("DB Init done")
}

func GetAllCronjobs() ([]structs.CronJob, error) {
	cronjobs := []structs.CronJob{}
	err := db.Select(&cronjobs, "SELECT id,active,schedule,bash,name,grp,description,severity,failsneeded,repeatnotifevery,alwaysnotify,notifygroup FROM cronjob")
	if err != nil {
		return cronjobs, err
	}
	return cronjobs, nil
}

func GetCronjob(name string) (structs.CronJob, error) {
	cj := structs.CronJob{}
	err := db.Get(&cj, "SELECT id,active,schedule,bash,name,grp,description,severity,failsneeded,repeatnotifevery,alwaysnotify,notifygroup FROM cronjob WHERE name = ?", name)
	if err != nil {
		return cj, err
	}
	return cj, nil
}

func GetAllNotifygroups() ([]structs.NotifyGroup, error) {
	notifygroups := []structs.NotifyGroup{}
	err := db.Select(&notifygroups, "SELECT * FROM notifygroup")
	if err != nil {
		return notifygroups, err
	}
	return notifygroups, nil
}

func GetLastLog(name string) (structs.CronJobLog, error) {
	cjl := structs.CronJobLog{}
	err := db.Get(&cjl, "SELECT * FROM cronjoblog WHERE name = ? ORDER BY id DESC LIMIT 1", name)
	if err != nil {
		return cjl, err
	}
	return cjl, nil
}

func GetLastLogs(name string, amount int) ([]structs.CronJobLog, error) {
	cjls := []structs.CronJobLog{}
	err := db.Select(&cjls, "SELECT * FROM cronjoblog WHERE name = ? ORDER BY id DESC LIMIT ?", name, amount)
	if err != nil {
		return cjls, err
	}
	return cjls, nil
}

func GetNotifyGroup(name string) (structs.NotifyGroup, error) {
	ng := structs.NotifyGroup{}
	err := db.Get(&ng, "SELECT * FROM notifygroup WHERE name = ?", name)
	if err != nil {
		return ng, err
	}
	return ng, nil
}

// Setters

func AddCronjob(cj structs.CronJob) error {
	_, err := db.NamedExec("REPLACE INTO cronjob(active,schedule,bash,name,grp,description,severity,failsneeded,repeatnotifevery,alwaysnotify,notifygroup) VALUES (:active,:schedule,:bash,:name,:grp,:description,:severity,:failsneeded,:repeatnotifevery,:alwaysnotify,:notifygroup)", cj)
	return err
}

func AddCronjobLog(cjl structs.CronJobLog) error {
	_, err := db.NamedExec("INSERT INTO cronjoblog(success,name,output,err) VALUES(:success,:name,:output,:err)", cjl)
	return err
}

func DeleteCronjob(dj structs.DeleteStruct) error {
	_, err := db.NamedExec("DELETE FROM cronjob WHERE name = :name", dj)
	return err
}

func SetCronjobStatus(ds structs.DeleteStruct, shouldBeActive bool) error {
    if shouldBeActive {
        _, err := db.NamedExec("UPDATE cronjob SET active = true WHERE name = :name", ds)
        return err
    }else{
        _, err := db.NamedExec("UPDATE cronjob SET active = false WHERE name = :name", ds)
        return err
    }
}

func AddNotifygroup(ng structs.NotifyGroup) error {
	_, err := db.NamedExec("REPLACE INTO notifygroup(name,gotifyurl,gotifykey,emailaddresses,webhookurl,shouldemail,shouldgotify,shouldwebhook) VALUES(:name,:gotifyurl,:gotifykey,:emailaddresses,:webhookurl,:shouldemail,:shouldgotify,:shouldwebhook)", ng)
	return err
}

func DeleteNotifygroup(ng structs.DeleteStruct) error {
	_, err := db.NamedExec("DELETE FROM notifygroup WHERE name = :name", ng)
	return err
}
