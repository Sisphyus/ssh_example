package main

import (
	"github.com/wingedpig/loom"
	"fmt"
	"net/http"
	"encoding/json"
	"log"
	"io/ioutil"
	"bytes"
	"strconv"
	"golang.org/x/crypto/ssh"
	"time"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"flag"
)

type AUTH struct {
	username string
	password string
}

type Request struct {
	Url string
	token string
}

type Token_Response struct{
	Expired_at string
	Expires_in int
	Token string
}

type Vpes struct {
	Sn string
	Company string
	Cds string
	Device_uuid string
	Type string
	Name string
	Cpu_used float32
	Memory_used float32
	Version string
	Updated_at string
}

type Meta struct {
	Count int
}

type Vpe_Response struct {
	Vpes []Vpes
	Meta Meta
}

type Icache_Response struct {
	Icaches []Icaches
	Meta Meta
}

type Icaches struct {
	Sn string
	Cds string
	Company string
	Ssh_host string
	Ssh_port int
	Http_port int
	Http_url string
	Https_port int
	Https_url string
	Monitor_url string
	Device_uuid string
	Type string
	Cpu_type string
	Cpu_used float32
	Memory_size_mb float32
	Memory_used float32
	Sys_disk_size_byte int
	Sys_disk_used float32
	Data_disk_size_byte int
	Data_disk_used float32
	Data_disk_status int
	Network_status int
	Version string
	Updated_at string
}

type Node_conf struct {
	Downlog_uri string
	Pn_title string
	Check_uri string
	Host string
	Sn string
	Update_uri string
}

func (req *Request)Get_token() string{

	client := &http.Client{}
	auth := map[string]string{"username":"tangyj", "password":"jnOL9OPFgtKY"}
	v, _ := json.Marshal(auth)
	request, err := http.NewRequest("POST",
		"https://oss.fxdata.cn/v1/auth/tokens",
		bytes.NewBuffer(v))
	if err != nil{
		log.Fatalf("create request failed\n:%v\n", err)
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil{
		log.Fatalf("handle error!\n:%v\n", err)
	}
	var result Token_Response
	err = json.Unmarshal(body, &result)
	if err != nil{
		log.Fatalf("Unmarshal failed!\n:%v\n", err)
	}
	return result.Token
}

func Standard_request(Url, token string) ([]byte ,error){

	client := &http.Client{}
	request, err := http.NewRequest("GET", Url, nil)
	if err != nil{
		log.Fatalf("create request failed\n:%v\n", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("X-auth-token",token)
	resp, err := client.Do(request)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil{
		return body ,err
	}
	return body ,nil
}

func (req *Request)Get_vpe() []Vpes{
	body ,err:= Standard_request(req.Url,req.token)
	var result Vpe_Response
	err = json.Unmarshal(body, &result)
	if err != nil{
		log.Fatalf("Unmarshal failed!\n:%v\n", err)
	}
	return result.Vpes

}

func (req *Request)Get_icache() []Icaches{
	body ,err:= Standard_request(req.Url,req.token)
	var result Icache_Response
	err = json.Unmarshal(body, &result)
	if err != nil{
		log.Fatalf("Unmarshal failed!\n:%v\n", err)
	}
	return result.Icaches

}

/*func Jump_to_vpe(host1 string) {
	sshClt, err := ssh.Dial("tcp", host1, &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password("FxData!Cds@2016_")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatalf("ssh.Dial(%q) failed: %v", host1, err)
	}
	defer sshClt.Close()

	e, _, err := expect.SpawnSSH(sshClt, timeout)
	if err != nil {
		log.Fatalf("failed: %v", err)
	}
	defer e.Close()
	e.Send("ls")
}*/

func connect(user, password, host string, port int) (*ssh.Session, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		client       *ssh.Client
		session      *ssh.Session
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if client, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	// create session
	if session, err = client.NewSession(); err != nil {
		return nil, err
	}

	return session, nil
}

func Jump_to_vpe(port int, vpe_host string) {
	session, err := connect("root", "FxData!Cds@2016_", "rhelp.fxdata.cn", port)
	if err != nil {
		log.Fatal(err)
	}
	//defer session.Close()

	fd := int(os.Stdout.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		panic(err)
	}
	//defer terminal.Restore(fd, oldState)

	// excute command
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		panic(err)
	}

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		log.Fatal(err)
	}

	session.Run("ssh -o stricthostkeychecking=no " + vpe_host)
	terminal.Restore(fd, oldState)
	os.Exit(0)

	err = session.Shell()
	if err != nil {
		panic(err)
	}
	err = session.Wait()
	if err != nil {
		panic(err)
	}
}


func main(){
	number := flag.String("sn","CAS0530000240","Serial Number")
	flag.Parse()
	a := &Request{}
	token := a.Get_token()
	//	fmt.Println(token)
	//	if str, ok := token.(string); ok{
	//		fmt.Println(str)
	//	}else {
	//		fmt.Println("not string")
	//	}
	a.token = token
	//	a.Url = "https://oss.fxdata.cn/v1/vpes?type=xingyu&cds=CAS0530000240"
	a.Url = "https://oss.fxdata.cn/v1/icaches?cds=" + *number
	icache_return := a.Get_icache()

	ice_host := icache_return[0].Ssh_host + ":" + strconv.Itoa(icache_return[0].Ssh_port)
	ssh_client := &loom.Config{
		User: "root",
		Password: "FxData!Cds@2016_",
		Host: ice_host,
		DisplayOutput: false,
	}
	b ,_ := ssh_client.Run("cat /home/f2cdn/cdn_node.conf")
	c := []byte(b)
	var conf []Node_conf
	err := json.Unmarshal(c, &conf)
	if err != nil{
		log.Fatalf("Unmarshal failed!\n:%v\n", err)
	}
	for _, value := range conf {
		if value.Pn_title == "xingyu" {
			Jump_to_vpe(icache_return[0].Ssh_port,value.Host)
		}
	}
}
