package models

import "gorm.io/gorm"

type Role string

const (
	AdminRole Role = "admin"
	UserRole  Role = "user"
)

type User struct {
	gorm.Model
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	UserName  string `gorm:"unique"`
	Password  string
	Role      string `json:"role" gorm:"not null"`
}
