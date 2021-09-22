package control

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"net/rpc"
	"os"
	"strings"
)




type Params struct{

	Width,Height int
	SrcIp string;
	Ips  []string

}



func FullMesh(c *gin.Context) {

	//查询需要fullmesh的ip
	 file,err :=  os.Open("config/iplist.txt")
	 if err != nil{

	 	panic(err)
	 }

	 defer file.Close()

	content,_:= ioutil.ReadAll(file)

	fmt.Println(string(content))

    tempArray := strings.Split(string(content),"\n")

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

				err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{50,10,v,tempArray}, &ret)

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
			err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{50,100,v,tempArray}, &ret)

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
			err1 := rpc.Call("VPC25Cube.FullMeshPing", Params{50,1000,v,tempArray}, &ret)

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
