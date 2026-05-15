package db

import (
	"fmt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func OrderFindInSet(session *gorm.DB, column, str string) *gorm.DB {
	session = session.Order(clause.Expr{
		SQL:  fmt.Sprintf("find_in_set(%s, ?) DESC", column),
		Vars: []interface{}{str},
	})
	return session
}
