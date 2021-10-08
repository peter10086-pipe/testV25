package control

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-multierror"
	"github.com/parnurzeal/gorequest"
	"github.com/sirupsen/logrus"
	cu "github.com/ucloud/ucloud-sdk-go/services/cube"
	"github.com/ucloud/ucloud-sdk-go/services/uhost"
	h "github.com/ucloud/ucloud-sdk-go/services/uhost"
	"github.com/ucloud/ucloud-sdk-go/ucloud"
	"github.com/ucloud/ucloud-sdk-go/ucloud/auth"
	ulog "github.com/ucloud/ucloud-sdk-go/ucloud/log"
	"github.com/ucloud/ucloud-sdk-go/ucloud/request"
	"github.com/ucloud/ucloud-sdk-go/ucloud/response"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/rpc"
	"strconv"
	"strings"
	"sync"
	"time"
	host "testV25/host"
)

const (
	backend      = "UVPCFEGO"
	url          = "http://api.ucloud.cn"
	internal     = "http://internal.api.ucloud.cn/"
	preInternal  = "http://internal.api.pre.ucloudadmin.com"
	pre2Internal = "http://10.64.76.5"
)

type (
	UCloudEnv struct {
		ulog.Logger
		Region string
		Zone  string
		cub            *cu.CubeClient
		uhost           *host.UHostClient
		hosts          map[string]*uhost.UHostInstanceSet
		host           *h.UHostClient
		cubes          map[string]*PodDetailInfo
		vpcfego         *VpcfeClient
		Cliens         map[string]*ssh.Session
		VPCId          string
		SubnetId       string
		HostIp         string
		SetId          string
		ImageId        string
		SecurityGroupId string
		PublicKey        string
		PrivateKey      string
		ProjectId       string
		Count           string
		RunCmd          string
	}
	TestInfo struct {
		ulog.Logger
		Region	string
		Zone    string
		ProjectId string
		PubK string
		PriK string
		VPCId string
		SubnetId string
		ImageId string
	}

)


var u *UCloudEnv
//func init(){
//	u = NewUCloudEnv()
//}

func (u *UCloudEnv) NewUCloudEnv() *UCloudEnv {
	config := ucloud.NewConfig()
	config.BaseUrl = url
	config.Region = u.Region
	config.Zone =  u.Zone
	config.ProjectId =u.ProjectId//"org-0x4kng"

	if lvl, e := logrus.ParseLevel("debug"); e != nil {
		panic(e)
	} else {
		config.LogLevel = ulog.Level(lvl)
	}

	credential := auth.NewCredential()
	credential.PrivateKey = u.PrivateKey//PubK//"EPToanhc560W5FzG1Zbq0QQK3h3kkf7hDOFyCv59SbCj68D9rOKp5sFzern9ULS5"
	credential.PublicKey = u.PublicKey//"gik0jB0CNWWgIbHrIr6ig3kIxrc0IoqTvu/huqf9u0ZRxA/8FEFUnxq7zOia8m2g"


	u = &UCloudEnv{
		Logger:       ulog.New(), // ulog.New(),
		cub:          cu.NewClient(&config,&credential),
		hosts:        make(map[string]*uhost.UHostInstanceSet),
		vpcfego:      NewVPCClient(&config,&credential),
		uhost:	      host.NewClient(&config,&credential),
		host:		  h.NewClient(&config,&credential),
		cubes:        make(map[string]*PodDetailInfo),
		VPCId :         u.VPCId,
		SubnetId  :     u.SubnetId,
		HostIp  :       u.HostIp,
		SetId  :        u.SetId,
		ImageId :       u.ImageId,
		SecurityGroupId: u.SecurityGroupId,
		PublicKey   :     u.PublicKey,
		PrivateKey  :    u.PrivateKey,
		ProjectId   :    u.ProjectId,
		Count      :     u.Count,
		Zone: 				u.Zone,
		RunCmd      : u.RunCmd,

	}
	fmt.Println(u)
	return u
}


func (u *UCloudEnv) describeHost(id string) []uhost.UHostInstanceSet {
	req := u.host.NewDescribeUHostInstanceRequest()
	//req.SetRetryable(true)
	//req.SetRetryCount(10)
	req.Tag = ucloud.String("vpc25")
	req.Zone = ucloud.String("")
	if id != "" {
		req.UHostIds = []string{id}
	}
	req.Limit = ucloud.Int(10000)
	req.Offset = ucloud.Int(0)

	for i := 0; i <= 60; i++ {
		resp, e := u.host.DescribeUHostInstance(req)
		if e != nil {
			//FailF(e, "DescribeUHostInstance")
			continue
		} else {
			return resp.UHostSet
		}
	}

	return nil
}


func (u *UCloudEnv) CreateHost() error{
	req := u.uhost.NewCreateUHostInstanceRequest()
	req.SetRetryCount(10)
	req.SetRetryable(true)
	req.WithTimeout(time.Second * 60)

	req.Tag = ucloud.String("vpc25")
	////if image := u.DescribeImage(); image != "" {
	//	req.ImageId = ucloud.String("")
	////} else {
	if u.ImageId == ""{
		req.ImageId = ucloud.String("uimage-gxl5au")
	}else{
		req.ImageId = ucloud.String(u.ImageId)
	}
	////}
	req.MinimalCpuPlatform = ucloud.String(`Intel/Auto`)
	//
	req.Disks = []host.UHostDisk{
				{
					IsBoot: ucloud.String("true"),
					Type:   ucloud.String("CLOUD_RSSD"),
					Size:   ucloud.Int(20),
				},
				{
					IsBoot: ucloud.String("false"),
					Type:   ucloud.String("CLOUD_RSSD"),
					Size:   ucloud.Int(20),
				},
			}
	//
	//	u.Infof("UHostDisk is set success %v", req.Disks)
    //   req.ImageId = ucloud.String(imageId)
	//
	req.MachineType = ucloud.String("O")
	req.LoginMode = ucloud.String("Password")
	req.Password = ucloud.String("gauge_auto_test")
	req.ChargeType = ucloud.String("Dynamic")
	req.CPU = ucloud.Int(1)
	req.Memory = ucloud.Int(1024)
   if u.SecurityGroupId ==""{
	   req.SecurityGroupId = ucloud.String("345327")
   }else{
	   req.SecurityGroupId = ucloud.String(u.SecurityGroupId)
   }
	rand.Seed(time.Now().UnixNano())
	subnet := []string{"subnet-pamsogsq","subnet-2zrg1sfg","subnet-xhmq3mdo","subnet-cg0jc5yc"}[rand.Intn(3)]

	vpc := map[string]string{"subnet-pamsogsq":"uvnet-15i4vykv","subnet-2zrg1sfg":"uvnet-15i4vykv","subnet-xhmq3mdo":"uvnet-15i4vykv","subnet-cg0jc5yc":"uvnet-brq13tlk"}





	req.SubnetId = ucloud.String(subnet)
	if u.SubnetId != ""{
		req.SubnetId = ucloud.String(u.SubnetId)
	}

	req.VPCId = ucloud.String(vpc[subnet])
	if u.VPCId !=""{
		req.VPCId = ucloud.String(u.VPCId)
	}


	IP := []string{"10.66.144.195","10.66.144.138"}[rand.Intn(2)]


	req.HostIp = ucloud.String(IP)
	if u.HostIp != ""{
		req.HostIp = ucloud.String(u.HostIp)
	}
	req.Name = req.HostIp
	req.SetId = ucloud.Int(16)
	if u.SetId != ""{
		v,_ := strconv.Atoi(u.SetId)
		req.SetId = ucloud.Int(v)
	}
	resp, e := u.uhost.CreateUHostInstance(req)
	if e != nil {
		//panic(e)
		return e
	}


	obj := u.describeHost(resp.UHostIds[0])[0]
	AddMacGray(obj.IPSet[0].Mac)
	req2 := u.host.NewModifyUHostInstanceRemarkRequest()
	req2.UHostId = ucloud.String(resp.UHostIds[0])
	req2.Remark=&obj.IPSet[0].Mac
	u.host.ModifyUHostInstanceRemark(req2)
	u.hosts[resp.UHostIds[0]] = &obj
	return nil
}



type (
	VpcfeClient struct {
		*ucloud.Client
	}
)


func NewVPCClient(config *ucloud.Config, credential *auth.Credential) *VpcfeClient {
	meta := ucloud.ClientMeta{Product: "VPC2.0"}
	client := ucloud.NewClientWithMeta(config, credential, meta)
	return &VpcfeClient{
		client,
	}
}

type Params struct{
	SrcIp string;
	DstIp string
	Ips  []string
}

type EIPAddr struct {
	IP           string
	OperatorName string
}

type PodInfo struct {
	Metadata struct {
	CubeId string `yaml:"cubeId"`
	} `yaml:"metadata"`

	Status struct {
	PodIp             string           `yaml:"podIp"`
	StartTime         string           `yaml:"startTime"`
	ContainerStatuses []ContainerStuct `yaml:"containerStatuses"`
	}
}

type ContainerStuct struct {
	State struct {
		Running struct {
		StartedAt string `yaml:"startedAt"`
		} `yaml:"running"`
	} `yaml:"state"`
}


type  PodDetailInfo struct {
	CubeId        string
	EIP           EIPAddr
	IP            string
	Mac           string
	CreateTime    int64
	RunningTime   int64
	StartPingTime int64
}

type IGetIpInfoByObjectRequest struct {
	Backend             string
	Az_group            uint32 `json:"az_group" required:"true"`
	Action              string
	Organization_id     uint32 `json:"organization_id" required:"true"`
	Top_organization_id uint32 `json:"top_organization_id" required:"true"`
	InstanceId          string `json:"InstanceId.0" required:"true"`
	request.CommonBase
}

type (
	IGetIpInfoByObjectResponse struct {
		DataSet []ObjectInfo
		response.CommonBase
	}

	ObjectInfo struct {
		Gateway      string
		InstanceId   string
		InterfaceId  string
		MacAddress   string
		Mode         string
		Netmask      string
		PrivateIpSet []string
		SubnetId     string
		VPCId        string
	}
)


func (fe *VpcfeClient) NewIGetIpInfoByObjectRequest() *IGetIpInfoByObjectRequest {
	req := &IGetIpInfoByObjectRequest{}
	// setup request with client config
	fe.Client.SetupRequest(req)

	req.Backend = "UVPCFEGO"
	req.Action = "IGetIpInfoByObject"

	// setup retryable with default retry policy (retry for non-create action and common error)
	req.SetRetryable(true)
	return req
}

func JoinErrors(es []error) error {
	vals := make([]string, 0, len(es))
	for _, e := range es {
		vals = append(vals, e.Error())
	}
	return fmt.Errorf(strings.Join(vals, ";"))
}

func RequestError(httpRes gorequest.Response, body string, errs []error, res interface{}) error {
	if errs != nil {
		return multierror.Prefix(JoinErrors(errs), "http send error:")
	}
	if httpRes.StatusCode != http.StatusOK {
		return fmt.Errorf("http status=%d, body=%s", httpRes.StatusCode, body)
	}
	if err := json.Unmarshal([]byte(body), res); err != nil {
		return multierror.Prefix(err, "json unmarshal error:")
	}
	return nil
}


func (fe *VpcfeClient) jsonInvokeAction(region string, req, res interface{}) error {
	var url string
	switch region {
	case "pre":
		url = preInternal
	case "pre2":
		url = pre2Internal
	default:
		url = internal
	}
	_res, body, errs := gorequest.New().Post(url).Type("json").Timeout(10 * time.Second).SendStruct(req).End()
	return RequestError(_res, body, errs, &res)
}


func (fe *VpcfeClient) IGetIpInfoByObject(req *IGetIpInfoByObjectRequest) (*IGetIpInfoByObjectResponse, error) {
	var res IGetIpInfoByObjectResponse
	err := fe.jsonInvokeAction(req.GetRegion(), req, &res)

	// log
	l := fe.Client.GetLogger()
	reqs, _ := json.Marshal(req)
	ress, _ := json.Marshal(res)

	l.Debugf("%s: %s", req.Action, reqs)
	l.Debugf("%s: %s", res.Action, ress)
	return &res, err
}

func (u *UCloudEnv) IGetIpInfoByObject(cubeId string) (string, error) {

	req := u.vpcfego.NewIGetIpInfoByObjectRequest()
	req.Az_group = 1000009
	req.Organization_id = 63874663
	req.Top_organization_id = 56006266
	//req.Zone = ucloud.String("")
	//req.Region = ucloud.String("")
	//req.ProjectId = ucloud.String("")
	//req.InstanceId[0] = cubeId

	req.InstanceId = cubeId
	//u.cube.GetCubePod()
	resp, err := u.vpcfego.IGetIpInfoByObject(req)
	if err != nil {
		return "", fmt.Errorf("IGetIpInfoByObject:%v", err)
	}

	return resp.DataSet[0].MacAddress, nil
}



func (u *UCloudEnv) GetCubeExtendInfo(ids string) error {

	req := u.cub.NewGetCubeExtendInfoRequest()
	req.CubeIds = ucloud.String(ids)
	req.Zone = ucloud.String("")
	resp, err := u.cub.GetCubeExtendInfo(req)
	if err != nil {
		return err
	}

	for _, cubeInfo := range resp.ExtendInfo {

		var pod = &PodDetailInfo{}
		pod.CubeId = cubeInfo.CubeId
		for _, ceip := range cubeInfo.Eip {
			if len(ceip.EIPAddr) != 0 {
				pod.EIP.IP = ceip.EIPAddr[0].IP
				pod.EIP.OperatorName = ceip.EIPAddr[0].OperatorName

			}

		}

		u.cubes[cubeInfo.CubeId] = pod
	}
	return nil

}

func (u *UCloudEnv) ListCubePod() error {

	//
	var pods string
	req := u.cub.NewListCubePodRequest()
	req.Limit = ucloud.Int(9999)
	req.Zone = ucloud.String("")
	//更新主机信息
	resp, err := u.cub.ListCubePod(req)
	if err != nil {
		return err
	}

	Pod := &PodInfo{}

	var mapIps = make(map[string]*PodDetailInfo)

	for _, v := range resp.Pods {

		sDec, err := base64.StdEncoding.DecodeString(v)
		if err != nil {

			return errors.New("DecodeString error")
		}

		// u.Infof("%v", string(sDec))

		err = yaml.Unmarshal(sDec, Pod)
		if err != nil {

			u.Errorf("%v", err)
			return err
		}

		PodDetailstruct := &PodDetailInfo{}
		PodDetailstruct.CubeId = Pod.Metadata.CubeId
		PodDetailstruct.IP = Pod.Status.PodIp
		//2021-06-16T02:53:21Z
		timeTemplate := "2006-01-02T15:04:05Z"
		st, _ := time.ParseInLocation(timeTemplate, Pod.Status.StartTime, time.Local)
		rt, _ := time.ParseInLocation(timeTemplate, Pod.Status.ContainerStatuses[0].State.Running.StartedAt, time.Local)
		PodDetailstruct.CreateTime = st.Unix() + 28800
		PodDetailstruct.RunningTime = rt.Unix() + 28800

		u.Infof("Podip is %v,%v,%v", Pod, Pod.Status.PodIp, PodDetailstruct)

		mapIps[Pod.Metadata.CubeId] = PodDetailstruct
		// mapIps[Pod.Metadata.CubeId].IP = Pod.Status.PodIp
		// mapIps[Pod.Metadata.CubeId].CreateTime = Pod.Status.StartTime
		// mapIps[Pod.Metadata.CubeId].RunningTime = Pod.Status.ContainerStatuses[0].Running.StartedAt

		pods = Pod.Metadata.CubeId + `,` + pods

	}

	u.GetCubeExtendInfo(pods)

	for i, v := range mapIps {

		u.cubes[i].IP = v.IP
		u.cubes[i].CreateTime = v.CreateTime
		u.cubes[i].RunningTime = v.RunningTime
	}
    //var mtex1 sync.WaitGroup
	//var mloc sync.RWMutex
	//for _, v := range u.cubes {
	//	mtex1.Add(1)
	//
	//	go func( pod *PodDetailInfo){
	//		defer mtex1.Done()
	//		mac, err := u.IGetIpInfoByObject(pod.CubeId)
	//		if err != nil {
	//			u.Errorf("IGetIpInfoByObject:", err)
	//		}
	//		mloc.Lock()
	//		u.cubes[pod.CubeId].Mac = mac
	//		AddMacGray(mac)
	//		AddMacFlow(mac)
	//		u.Infof("%v,%v,%v,%v,%v,%v", pod.IP, pod.CubeId, pod.EIP.IP, pod.CreateTime, pod.RunningTime, mac)
	//		mloc.Unlock()
	//	}(v)
	//
	//}
	//
	//mtex1.Wait()

	u.Infof("%v,%v,%v,%v", u.cubes)

	u.Infof("%v", u.cubes)
	return nil

}


func CreateCubePod(c *gin.Context ) {

	u =  GetInfo(c)
	u = u.NewUCloudEnv()
	yamlstr := `YXBpVmVyc2lvbjogdjFiZXRhMQpraW5kOiBQb2QKc3BlYzoKICBjb250YWluZXJzOgogICAgLSBuYW1lOiBjdWJlMDEKICAgICAgaW1hZ2U6ICd1aHViLnNlcnZpY2UudWNsb3VkLmNuL3VjbG91ZC9jZW50b3M3LXNzaDpsYXRlc3QnCiAgICAgIGVudjoKICAgICAgICAtIG5hbWU6IFBBU1NXRAogICAgICAgICAgdmFsdWU6IGdhdWdlX2F1dG9fdGVzdAogICAgICByZXNvdXJjZXM6CiAgICAgICAgbGltaXRzOgogICAgICAgICAgbWVtb3J5OiAxMDI0TWkKICAgICAgICAgIGNwdTogMTAwMG0KICAgICAgdm9sdW1lTW91bnRzOiBbXQogIHZvbHVtZXM6IFtdCiAgcmVzdGFydFBvbGljeTogQWx3YXlzCg==`
	//
	time.Sleep(time.Millisecond*1)
	req := u.cub.NewCreateCubePodRequest()
	req.Pod = ucloud.String(yamlstr)
	req.SubnetId = ucloud.String(u.SubnetId)
	req.Tag = ucloud.String("vpc25")
	req.VPCId = ucloud.String(u.VPCId)
	req.Zone = ucloud.String(u.Zone)

	Count ,err1 := strconv.Atoi(u.Count)
	if err1 !=nil{
		Count = 5
	}
	//更新主机信息
	var flg bool
	var mtx sync.WaitGroup
	for i:=0;i<Count;i++{
		mtx.Add(1)
		go func(){
			defer mtx.Done()
			resp, err := u.cub.CreateCubePod(req)

			u.Infof("resp %v %s ",err,resp)
			if err != nil {
				//return err

				flg =true
			}
			if resp.RetCode != 0 {
				//return err

				flg =true
			}
			logStr := fmt.Sprint("创建cube%s(%s)", req.SubnetId, resp.CubeId)
			fmt.Println(logStr)

			// bind eip
			cubeInf := &PodDetailInfo{}
			cubeInf.CubeId = resp.CubeId

			u.cubes[resp.CubeId] = cubeInf
		}()
	}
	mtx.Wait()
	// u.AllocateEIP(resp.CubeId, 1, "Month", "Bandwidth", 0)

	// u.BindEIP(resp.CubeId, "cube", resp.CubeId)

	time.Sleep(time.Second * 2)
	if flg{
		c.JSON(http.StatusOK, gin.H{
			"retcode": "-1",
			"message":"create fail",
		})
		return
	}else{
		c.JSON(http.StatusOK, gin.H{
			"retcode": "0",
			"message":"create success",
		})
		return
	}

}


func PodIperf(c *gin.Context) {
	u =  GetInfo(c)
	u = u.NewUCloudEnv()
	u.ListCubePod()

	//objs := u.describeHost("")

	//ips := make([]string,0)
	var tempArray = make([]string,0)

	for _,v:=range u.cubes{
		tempArray = append(tempArray,v.IP)
		//AddMacGray(v.IPSet[0].Mac)
		//AddMacFlow(v.IPSet[0].Mac)
	}
	//for i,v:=range u.cubes{
	//	fmt.Println(i,v.IP)
	//	tempArray = append(tempArray,v.IP)
	//}
	ret := 0
	var mtex sync.WaitGroup
	rpc, err := rpc.DialHTTP("tcp","106.75.254.85:8082")
	if err !=nil{

		c.JSON(http.StatusBadRequest, gin.H{
			"retcode": "-1",
			"message":err.Error(),
		})
		return
	}

	for i, v:= range tempArray {
		mtex.Add(1)
		if i < len(tempArray)/2{
			go func(Sip ,Dip string ,ips []string, res *int){
				defer mtex.Done()
				err1 := rpc.Call("VPC25Cube.Iperf", Params{Sip,Dip,ips}, &res)

				if err1 != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"retcode": "-1",
						"message":err1.Error(),
					})
					return
				}
				//执行远程调用

			}(v,tempArray[len(tempArray)-1-i],tempArray,&ret)

		}

	}

	mtex.Wait()

	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
		"ret":ret,

	})
	return


}


//func PodIperf(c *gin.Context) {
//	u =  GetInfo(c)
//	u = u.NewUCloudEnv()
//	u.ListCubePod()
//    var tempArray = make([]string,0)
//	for i,v:=range u.cubes{
//		fmt.Println(i,v.IP)
//		tempArray = append(tempArray,v.IP)
//	}
//	ret := 0
//	var mtex sync.WaitGroup
//
//	for i, v:= range tempArray {
//			mtex.Add(1)
//			if i < len(tempArray)/2{
//				go func(Sip ,Dip string ,ips []string, res *int){
//					defer mtex.Done()
//					rpc, err := rpc.DialHTTP("tcp","106.75.254.85:8082")
//					if err !=nil{
//
//						c.JSON(http.StatusBadRequest, gin.H{
//							"retcode": "-1",
//							"message":err.Error(),
//						})
//						return
//					}
//
//						err1 := rpc.Call("VPC25Cube.ServerIperf", Params{Sip,Dip,ips}, &res)
//
//						if err1 != nil {
//							c.JSON(http.StatusBadRequest, gin.H{
//								"retcode": "-1",
//								"message":err1.Error(),
//							})
//							return
//						}
//						//执行远程调用
//
//					}(v,tempArray[len(tempArray)-1-i],tempArray,&ret)
//
//			}
//
//	}
//
//	mtex.Wait()
//
//	c.JSON(http.StatusOK, gin.H{
//		"message": "pong",
//		"ret":ret,
//
//	})
//	return
//
//
//}


func HostIperf(c *gin.Context) {
	u =  GetInfo(c)
	u = u.NewUCloudEnv()
	//u.ListCubePod()

	objs := u.describeHost("")

	//ips := make([]string,0)
	var tempArray = make([]string,0)

	for _,v:=range objs{
		tempArray = append(tempArray,v.IPSet[0].IP)
		//AddMacGray(v.IPSet[0].Mac)
		//AddMacFlow(v.IPSet[0].Mac)
	}
	//for i,v:=range u.cubes{
	//	fmt.Println(i,v.IP)
	//	tempArray = append(tempArray,v.IP)
	//}
	ret := 0
	var mtex sync.WaitGroup
	rpc, err := rpc.DialHTTP("tcp","106.75.254.85:8082")
	if err !=nil{

		c.JSON(http.StatusBadRequest, gin.H{
			"retcode": "-1",
			"message":err.Error(),
		})
		return
	}

	for i, v:= range tempArray {
		mtex.Add(1)
		if i < len(tempArray)/2{
			go func(Sip ,Dip string ,ips []string, res *int){
				defer mtex.Done()
				err1 := rpc.Call("VPC25Cube.Iperf", Params{Sip,Dip,ips}, &res)

				if err1 != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"retcode": "-1",
						"message":err1.Error(),
					})
					return
				}
				//执行远程调用

			}(v,tempArray[len(tempArray)-1-i],tempArray,&ret)

		}

	}

	mtex.Wait()

	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
		"ret":ret,

	})
	return


}


func PodFullMesh(c *gin.Context) {
	u =  GetInfo(c)
	u = u.NewUCloudEnv()
	u.ListCubePod()
	var tempArray = make([]string,0)
	for i,v:=range u.cubes{
		fmt.Println(i,v.IP)
		tempArray = append(tempArray,v.IP)
	}
	////查询需要fullmesh的ip
	// file,err :=  os.Open("config/iplist.txt")
	// if err != nil{
	//
	// 	panic(err)
	// }
	//
	// defer file.Close()
	//
	//content,_:= ioutil.ReadAll(file)
	//
	//fmt.Println(string(content))
	//
	//tempArray := strings.Split(string(content),"\n")

	ret := 0
	var mtex sync.WaitGroup
	//	for i, v:= range tempArray {
	mtex.Add(1)

	//	fmt.Println("current ip:",i,v)

	//初始化远程

	go func(ips []string, res *int){
		defer mtex.Done()
		rpc, err := rpc.DialHTTP("tcp","106.75.254.85:8082")
		if err !=nil{

			c.JSON(http.StatusBadRequest, gin.H{
				"retcode": "-1",
				"message":err.Error(),
			})
		}

		err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{"","",ips}, &res)

		if err1 != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"retcode": "-1",
				"message":err1.Error(),
			})
		}
		//执行远程调用

	}(tempArray,&ret)
	//case 1:
	//	go func(ip string,ips []string, res *int){
	//		defer mtex.Done()
	//		rpc, err := rpc.DialHTTP("tcp","10.2.202.109:8082")
	//		if err !=nil{
	//
	//			c.JSON(http.StatusBadRequest, gin.H{
	//				"retcode": "-1",
	//				"message":err.Error(),
	//			})
	//		}
	//
	//		err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{ip,ips}, &res)
	//
	//		if err1 != nil {
	//			c.JSON(http.StatusBadRequest, gin.H{
	//				"retcode": "-1",
	//				"message":err1.Error(),
	//			})
	//		}
	//		//执行远程调用
	//
	//	}(v,tempArray,&ret)
	//case 2:
	//	go func(ip string,ips []string, res *int){
	//		defer mtex.Done()
	//		rpc, err := rpc.DialHTTP("tcp","10.2.7.222:8082")
	//		if err !=nil{
	//
	//			c.JSON(http.StatusBadRequest, gin.H{
	//				"retcode": "-1",
	//				"message":err.Error(),
	//			})
	//		}
	//
	//		err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{ip,ips}, &res)
	//
	//		if err1 != nil {
	//			c.JSON(http.StatusBadRequest, gin.H{
	//				"retcode": "-1",
	//				"message":err1.Error(),
	//			})
	//		}
	//		//执行远程调用
	//
	//	}(v,tempArray,&ret)
	//}


	//}

	//登录所有ip


	mtex.Wait()


	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
		"ret":ret,

	})
	return


}

func (u *UCloudEnv) WaitHost(id string, state uhost.State) error {
	req := u.host.NewWaitUntilUHostInstanceStateRequest()
	req.State = state
	req.Interval = ucloud.TimeDuration(1 * time.Second)
	req.MaxAttempts = ucloud.Int(10)
	req.IgnoreError = ucloud.Bool(true)
	req.DescribeRequest = u.host.NewDescribeUHostInstanceRequest()
	req.DescribeRequest.UHostIds = []string{id}
	if e := u.host.WaitUntilUHostInstanceState(req); e != nil {
		return e
	}
	return nil
}

func CreateHost(c *gin.Context ) {

	u =  GetInfo(c)
	u = u.NewUCloudEnv()
	var mutex sync.WaitGroup

	count := 2
	if u.Count != ""{
		var err error
		count,err = strconv.Atoi(u.Count)
		if err !=nil{
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Count strconv fail",
				"ret":-1,

			})
			return
		}
	}
	//u = NewUCloudEnv()
	for i:=0;i<count;i++ {

		mutex.Add(1)
		go func(){
			defer mutex.Done()
			u.CreateHost()
		}()
	}
	mutex.Wait()
	var ips = make([]string,0)
	for _,v := range u.hosts{
		mutex.Add(1)
		go func(addr *uhost.UHostInstanceSet){
			defer mutex.Done()
			u.WaitHost(v.UHostId,"Running")
			ips = append(ips,addr.IPSet[0].IP)
			AddMacGray(addr.IPSet[0].Mac)
			AddMacFlow(addr.IPSet[0].Mac)
		}(v)
	}
	mutex.Wait()

	//rpc1, err := rpc.DialHTTP("tcp","106.75.254.85:8082")
	//if err !=nil{
	//	panic(err)
	//}
	//
	//var res int
	//err1 := rpc1.Call("VPC25Cube.FullMeshPing", Params{"",ips}, &res)
	//if err1 != nil{
	//	panic(err1)
	//}

	c.JSON(http.StatusOK, gin.H{
		"message": "CreateHost",
		"ret":0,

	})
	return
}

func AddMacGray(mac string){
	rand.Seed(time.Now().UnixNano())
	url := []string{"http://10.66.152.167:8010","http://10.66.152.166:8010","http://10.66.152.165:8010","http://10.66.152.164:8010"}[rand.Intn(4)]
	method := "POST"
	payload := strings.NewReader(`{
    "action":"AddMacGray",
    "mac":"`+ mac +`"
	}
	`)
	client := &http.Client {
	}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("add gray",string(body))
}

func AddMacFlow(mac string){
	rand.Seed(time.Now().UnixNano())
	url := []string{"http://10.66.152.155:7010"}
	method := "POST"
	payload := strings.NewReader(`{
    "action":"AddFlow",
    "mac":"`+ mac +`"
	}
	`)
	client := &http.Client {
	}
	req, err := http.NewRequest(method, url[0], payload)

	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("add gray",string(body))
}


func Gray(c *gin.Context ) {

	u =  GetInfo(c)
	u = u.NewUCloudEnv()
	u.ListCubePod()

	var mutex sync.WaitGroup

	for _,v:=range u.cubes {

		mutex.Add(1)
		go func(){
			defer mutex.Done()
			AddMacGray(v.Mac)
			AddMacFlow(v.Mac)
		}()
	}
	mutex.Wait()
	c.JSON(http.StatusOK, gin.H{
		"message": "Gray",
		"ret":0,

	})
	return
}

//func AddGrayForMac(c *gin.Context ) {
//	AddMacGray("52:54:00:B3:D8:C1")
//
//	c.JSON(http.StatusOK, gin.H{
//		"message": "Gray",
//		"ret":0,
//
//	})
//	return
//}
//func AddFlowForMac(c *gin.Context){
//	AddMacFlow("52:54:00:B3:D8:C1")
//
//	c.JSON(http.StatusOK, gin.H{
//		"message": "Gray",
//		"ret":0,
//
//	})
//	return
//
//}


func GetInfo(c *gin.Context) *UCloudEnv {


	var u = &UCloudEnv{}
	u.ProjectId = c.PostForm("ProjectId")
	u.VPCId = c.PostForm("VPCId")
	u.SubnetId = c.PostForm("SubnetId")
	u.PublicKey = c.PostForm("PublicKey")
	u.PrivateKey = c.PostForm("PrivateKey")
	u.SetId = c.PostForm("SetId")
	u.HostIp = c.PostForm("HostIp")
	u.SecurityGroupId= c.PostForm("SecurityGroupId")
	u.ImageId= c.PostForm("ImageId")
	u.Region= c.PostForm("Region")
	u.Zone= c.PostForm("Zone")
	u.Count = c.PostForm("Count")
	u.RunCmd = c.PostForm("Shell")

	fmt.Printf("ProjectId: %s; VpcId: %s; SubnetId: %s; Publikey: %s PrivateKey:%s Zone:%s Count：%s HostIp %s Shell %s", u.ProjectId, u.VPCId, u.SubnetId, u.PublicKey,u.PrivateKey,u.Zone,u.Count,u.HostIp,u.RunCmd)

	return u
}


func PingHost(c *gin.Context ) {

	u =  GetInfo(c)
	u = u.NewUCloudEnv()
	objs := u.describeHost("")

	ips := make([]string,0)

	for _,v:=range objs{
		ips = append(ips,v.IPSet[0].IP)
		//AddMacGray(v.IPSet[0].Mac)
		//AddMacFlow(v.IPSet[0].Mac)

	}

	rpc1, err := rpc.DialHTTP("tcp","106.75.254.85:8082")
	if err !=nil{
		//panic(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "PingHost",
			"ret":-1,

		})
		return
	}

	var res int
	err1 := rpc1.Call("VPC25Cube.FullMeshPing", Params{"","",ips}, &res)
	if err1 != nil{
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "PingHost",
			"ret":-1,

		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "PingHost",
		"ret":0,

	})
	return
}