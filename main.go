package main

import (
	"github.com/asme/crud-auth/controllers"
	"github.com/asme/crud-auth/initializers"
	"github.com/asme/crud-auth/middlewares"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.POST("/create", controllers.CreateUser)
	r.POST("/login", controllers.Login)

	r.Use(middlewares.Authentication(), middlewares.Authorization())

	r.GET("/get", controllers.GetUser)
	r.GET("/get/:id", controllers.GetUserByID)
	r.PUT("/update/:id", controllers.UpdateUser)
	r.DELETE("/delete/:id", controllers.DeleteUser)

	r.Run()
}
