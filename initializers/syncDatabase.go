package initializers

import "github.com/asme/crud-auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}