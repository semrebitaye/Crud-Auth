package middlewares

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/asme/crud-auth/initializers"
	"github.com/asme/crud-auth/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Authentication() gin.HandlerFunc {
	//get the Bearer of the req body
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if !(strings.HasPrefix(tokenString, "Bearer ")) {
			fmt.Println("bearer not found")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(tokenString, "Bearer ")

		//Decode/validateit
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(os.Getenv("SECRET")), nil
		})
		if err != nil {
			fmt.Print("Error validation", err)

			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			//check the exp
			if float64(time.Now().Unix()) > claims["exp"].(float64) {
				fmt.Print("Error expired", err)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			// fined the user with token sub
			var user models.User
			initializers.DB.First(&user, claims["sub"])

			if user.ID == 0 {

				err := errors.New("user not found")
				fmt.Print("Error not found", err)
				c.AbortWithError(http.StatusNotFound, err)
				return
			}

			// attach the req
			c.Set("user_id", user.ID)
			c.Set("role", user.Role)
			fmt.Println("user data: ", user.Role)

			//continue
			c.Next()
		} else {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}
}

func Authorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleInterface, exists := c.Get("role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		fmt.Printf("Type of roleInterface: %T\n", roleInterface)

		roleString, ok := roleInterface.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		method := c.Request.Method
		if models.Role(roleString) == (models.UserRole) {
			if method != http.MethodGet {
				err := errors.New("unauthorized user")
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

		}
		c.Next()
	}

}
