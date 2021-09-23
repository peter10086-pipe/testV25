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
	"github.com/ucloud/ucloud-sdk-go/ucloud"
	"github.com/ucloud/ucloud-sdk-go/ucloud/auth"
	ulog "github.com/ucloud/ucloud-sdk-go/ucloud/log"
	"github.com/ucloud/ucloud-sdk-go/ucloud/request"
	"github.com/ucloud/ucloud-sdk-go/ucloud/response"
	"gopkg.in/yaml.v2"
	"net/http"
	"net/rpc"
	"strings"
	"sync"
	"time"
)

const (
	backend      = "UVPCFEGO"
	internal     = "http://internal.api.ucloud.cn/"
	preInternal  = "http://internal.api.pre.ucloudadmin.com"
	pre2Internal = "http://10.64.76.5"
)

type (
	VpcfeClient struct {
		*ucloud.Client
	}
)

var u *UCloudEnv
func init(){
	u = NewUCloudEnv()
}


func NewVPCClient(config *ucloud.Config, credential *auth.Credential) *VpcfeClient {
	meta := ucloud.ClientMeta{Product: "VPC2.0"}
	client := ucloud.NewClientWithMeta(config, credential, meta)
	return &VpcfeClient{
		client,
	}
}

type  UCloudEnv struct {
	ulog.Logger
	cub            *cu.CubeClient
	cubes          map[string]*PodDetailInfo
	vpcfego          *VpcfeClient

}


type Params struct{
	SrcIp string;
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
    var mtex1 sync.WaitGroup
	var mloc sync.RWMutex
	for _, v := range u.cubes {
		mtex1.Add(1)

		go func( pod *PodDetailInfo){
			defer mtex1.Done()
			mac, err := u.IGetIpInfoByObject(v.CubeId)
			if err != nil {
				u.Errorf("IGetIpInfoByObject:", err)
			}
			mloc.Lock()
			u.cubes[v.CubeId].Mac = mac
			u.Infof("%v,%v,%v,%v,%v,%v", v.IP, v.CubeId, v.EIP.IP, v.CreateTime, v.RunningTime, mac)
			mloc.Unlock()
		}(v)

	}

	mtex1.Wait()

	//u.Infof("%v,%v,%v,%v", u.cubes)

	//u.Infof("%v", u.cubes)
	// gauge.WriteMessage("创建cube%s(%s)", req.SubnetId, resp.CubeId)

	return nil

}


func NewUCloudEnv() *UCloudEnv {
	config := ucloud.NewConfig()
	config.BaseUrl = "http://api.ucloud.cn"
	config.Region = "cn-sh2"
	config.Zone =  "cn-sh2-01"
	config.ProjectId ="org-0x4kng"

	if lvl, e := logrus.ParseLevel("debug"); e != nil {
		panic(e)
	} else {
		config.LogLevel = ulog.Level(lvl)
	}

	credential := auth.NewCredential()
	credential.PrivateKey = "EPToanhc560W5FzG1Zbq0QQK3h3kkf7hDOFyCv59SbCj68D9rOKp5sFzern9ULS5"
	credential.PublicKey = "gik0jB0CNWWgIbHrIr6ig3kIxrc0IoqTvu/huqf9u0ZRxA/8FEFUnxq7zOia8m2g"


	u := &UCloudEnv{
		Logger:       ulog.New(), // ulog.New(),
		cub:          cu.NewClient(&config,&credential),
		vpcfego:      NewVPCClient(&config,&credential),
		cubes:        make(map[string]*PodDetailInfo),
	}
	return u
}



func CreateCubePod(c *gin.Context ) {


	yamlstr := `YXBpVmVyc2lvbjogdjFiZXRhMQpraW5kOiBQb2QKc3BlYzoKICBjb250YWluZXJzOgogICAgLSBuYW1lOiBjdWJlMDEKICAgICAgaW1hZ2U6ICd1aHViLnNlcnZpY2UudWNsb3VkLmNuL3VjbG91ZC9jZW50b3M3LXNzaDpsYXRlc3QnCiAgICAgIGVudjoKICAgICAgICAtIG5hbWU6IFBBU1NXRAogICAgICAgICAgdmFsdWU6IGdhdWdlX2F1dG9fdGVzdAogICAgICByZXNvdXJjZXM6CiAgICAgICAgbGltaXRzOgogICAgICAgICAgbWVtb3J5OiAxMDI0TWkKICAgICAgICAgIGNwdTogMTAwMG0KICAgICAgdm9sdW1lTW91bnRzOiBbXQogIHZvbHVtZXM6IFtdCiAgcmVzdGFydFBvbGljeTogQWx3YXlzCg==`
	//
	req := u.cub.NewCreateCubePodRequest()
	req.Pod = ucloud.String(yamlstr)
	req.SubnetId = ucloud.String("subnet-pamsogsq")
	req.Tag = ucloud.String("vpc25")
	req.VPCId = ucloud.String("uvnet-15i4vykv")
	req.Zone = ucloud.String("cn-sh2-01")
	//更新主机信息
	var mtx sync.WaitGroup
	mtx.Add(1)
	for i:=0;i<50;i++{
		defer mtx.Done()

		go func(){
			resp, err := u.cub.CreateCubePod(req)

			u.Infof("resp %v %s ",err,resp)
			if err != nil {
				//return err

				c.JSON(http.StatusBadRequest, gin.H{
					"retcode": "-1",
					"message":err.Error(),
				})
				return
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
	c.JSON(http.StatusOK, gin.H{
		"retcode": "0",
		"message":"create success",
	})
	return
}


func FullMesh(c *gin.Context) {


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
	for i, v:= range tempArray {

		fmt.Println("current ip:",i,v)

			//初始化远程


		switch i%3 {

		case 0:

			rpc, err := rpc.DialHTTP("tcp","10.2.122.25:8082")
			if err !=nil{

				c.JSON(http.StatusBadRequest, gin.H{
					"retcode": "-1",
					"message":err.Error(),
				})
			}

				err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{v,tempArray}, &ret)

				if err1 != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"retcode": "-1",
						"message":err1.Error(),
					})
				}
				//执行远程调用

				fmt.Println(ret)
		case 1:
			rpc, err := rpc.DialHTTP("tcp","10.2.202.109:8082")
			if err !=nil{

				c.JSON(http.StatusBadRequest, gin.H{
					"retcode": "-1",
					"message":err.Error(),
				})
			}
			fmt.Println(v)
			fmt.Println(tempArray)
			err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{v,tempArray}, &ret)

			if err1 != nil {

				c.JSON(http.StatusBadRequest, gin.H{
					"retcode": "-1",
					"message":err1.Error(),
				})
			}
			//执行远程调用

			fmt.Println(ret)
		case 2:
			rpc, err := rpc.DialHTTP("tcp","10.2.7.222:8082")
			if err !=nil{

				c.JSON(http.StatusBadRequest, gin.H{
					"retcode": "-1",
					"message":err.Error(),
				})
			}
			err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{v,tempArray}, &ret)

			if err1 != nil {

				c.JSON(http.StatusBadRequest, gin.H{
					"retcode": "-1",
					"message":err1.Error(),
				})
			}
			//执行远程调用

			fmt.Println(ret)
		}
	}
	//登录所有ip





	c.JSON(http.StatusOK, gin.H{
		"message": "pong",
		"ret":ret,

	})


}
