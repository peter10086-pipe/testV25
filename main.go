package main

import "github.com/gin-gonic/gin"

import "testV25/control"

func main() {
	r := gin.Default()

	r.GET("/ping",control.FullMesh)
	r.Run() // listen and serve on 0.0.0.0:8080
}
