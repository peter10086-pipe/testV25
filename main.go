package main

import "github.com/gin-gonic/gin"

import "testV25/control"

func main() {
	r := gin.Default()
	r.POST("/CreatePod",control.CreateCubePod)
	r.POST("/CreateHost",control.CreateHost)
	r.POST("/PodGray",control.Gray)
	//r.GET("/addGray",control.AddGrayForMac)
	//r.GET("/addGray",control.AddFlowForMac)
	r.POST("/HostFullMesh",control.PingHost)
	r.POST("/PodFullMesh",control.PodFullMesh)
	r.POST("/RunPodIperf",control.PodIperf)
	r.POST("/RunHostIperf",control.HostIperf)
	r.Run() // listen and serve on 0.0.0.0:8080
}
