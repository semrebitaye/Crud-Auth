package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/asme/crud-auth/initializers"
	"github.com/asme/crud-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var userRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	UserName  string `json:"user_name"`
	Password  string `json:"password"`
	Role      string `json:"role"`
}

func CreateUser(c *gin.Context) {
	// get the data of the req body
	if c.Bind(&userRequest) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to read the body"})
		return
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(userRequest.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to hash the password"})
		return
	}

	// create user
	user := models.User{FirstName: userRequest.FirstName, LastName: userRequest.LastName, UserName: userRequest.UserName, Password: string(hash), Role: userRequest.Role}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to create user"})
	}

	// respond it
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func GetUser(c *gin.Context) {
	// get the user from the database
	var users []models.User
	result := initializers.DB.Find(&users)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to get the users"})
	}

	// respond it
	c.JSON(http.StatusOK, gin.H{"users": users})
}

func GetUserByID(c *gin.Context) {
	// get the id of the url body
	id := c.Param("id")

	// get the user from the database by the id
	var user models.User
	result := initializers.DB.First(&user, id)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to get the user"})
	}

	// respond it
	c.JSON(http.StatusOK, gin.H{"User": user})
}

func UpdateUser(c *gin.Context) {
	// get the id of the url
	id := c.Param("id")

	// get the data of the req body
	c.Bind(&userRequest)

	// fined the post where updating
	var user models.User
	result := initializers.DB.First(&user, id)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to get the user"})
	}

	// update it
	initializers.DB.Model(&user).Updates(models.User{FirstName: userRequest.FirstName, LastName: userRequest.LastName, UserName: userRequest.UserName, Role: userRequest.Role, Password: userRequest.Password})

	// respond it
	c.JSON(http.StatusOK, gin.H{"User": user})
}

func DeleteUser(c *gin.Context) {
	// get the id of url
	id := c.Param("id")

	// delete the user
	initializers.DB.Delete(&models.User{}, id)

	// respond it
	c.Status(200)
}

func Login(c *gin.Context) {
	// get username and password of req body
	if c.Bind(&userRequest) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to read the body"})
		return
	}

	//lockup requested user--
	var user models.User
	initializers.DB.First(&user, "user_name = ?", userRequest.UserName)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Invalid user name"})
		return
	}

	//compare sent in pass with saved pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userRequest.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Invalid Password"})
		return
	}

	// generate jwt tocken
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID,
		"role": user.Role,
		"exp":  time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"Error": "Failed to create tocken"})
		return
	}

	// send it back
	c.JSON(http.StatusOK, gin.H{"Tocken": tokenString})
}
