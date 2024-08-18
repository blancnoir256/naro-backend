package handler

import (
	"database/sql"
	"errors"
	"log"
	"net/http"

	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	db *sqlx.DB
}

func NewHandler(db *sqlx.DB) *Handler {
	return &Handler{db: db}
}

type City struct {
	ID          int            `json:"id,omitempty"  db:"ID"`
	Name        sql.NullString `json:"name,omitempty"  db:"Name"`
	CountryCode sql.NullString `json:"countryCode,omitempty"  db:"CountryCode"`
	District    sql.NullString `json:"district,omitempty"  db:"District"`
	Population  sql.NullInt64  `json:"population,omitempty"  db:"Population"`
}

type CityInput struct {
	ID          int    `json:"id,omitempty"  db:"ID"`
	Name        string `json:"name,omitempty"  db:"Name"`
	CountryCode string `json:"countryCode,omitempty"  db:"CountryCode"`
	District    string `json:"district,omitempty"  db:"District"`
	Population  int    `json:"population,omitempty"  db:"Population"`
}

func (h *Handler) GetCityInfoHandler(c echo.Context) error {
	cityName := c.Param("cityName")

	var city City
	err := h.db.Get(&city, "SELECT * FROM city WHERE Name=?", cityName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.NoContent(http.StatusNotFound)
		}
		log.Printf("failed to get city data: %s\n", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, city)
}

func (h *Handler) PostCityHandler(c echo.Context) error {
	var city CityInput
	err := c.Bind(&city)
	if err != nil {
		log.Printf("test: %s\n", err)
		return echo.NewHTTPError(http.StatusBadRequest, "bad request body")
	}

	result, err := h.db.Exec("INSERT INTO city (Name, CountryCode, District, Population) VALUES (?, ?, ?, ?)", city.Name, city.CountryCode, city.District, city.Population)
	if err != nil {
		log.Printf("failed to insert city data: %s\n", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Printf("failed to get last insert id: %s\n", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	city.ID = int(id)

	return c.JSON(http.StatusCreated, city)
}

type LoginRequestBody struct {
	Username string `json:"username,omitempty" form:"username"`
	Password string `json:"password,omitempty" form:"password"`
}

func (h *Handler) SignUpHandler(c echo.Context) error {
	// リクエストを受け取り、reqに格納する
	req := LoginRequestBody{}
	err := c.Bind(&req)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "bad request body")
	}

	// バリデーションする(PasswordかUsernameが空文字列の場合は400 BadRequestを返す)
	if req.Password == "" || req.Username == "" {
		return c.String(http.StatusBadRequest, "Username or Password is empty")
	}

	// 登録しようとしているユーザーが既にデータベース内に存在するかチェック
	var count int
	err = h.db.Get(&count, "SELECT COUNT(*) FROM users WHERE Username=?", req.Username)
	if err != nil {
		log.Println(err)
		return c.NoContent(http.StatusInternalServerError)
	}
	// 存在したら409 Conflictを返す
	if count > 0 {
		return c.String(http.StatusConflict, "Username is already used")
	}

	// パスワードをハッシュ化する
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	// ハッシュ化に失敗したら500 InternalServerErrorを返す
	if err != nil {
		log.Println(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	// ユーザーを登録する
	_, err = h.db.Exec("INSERT INTO users (Username, HashedPass) VALUES (?, ?)", req.Username, hashedPass)
	// 登録に失敗したら500 InternalServerErrorを返す
	if err != nil {
		log.Println(err)
		return c.NoContent(http.StatusInternalServerError)
	}
	// 登録に成功したら201 Createdを返す
	return c.NoContent(http.StatusCreated)
}

type User struct {
	Username   string `json:"username,omitempty"  db:"Username"`
	HashedPass string `json:"-"  db:"HashedPass"`
}

func (h *Handler) LoginHandler(c echo.Context) error {
	// リクエストを受け取り、reqに格納する
	var req LoginRequestBody
	err := c.Bind(&req)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad request body")
	}

	// バリデーションする(PasswordかUsernameが空文字列の場合は400 BadRequestを返す)
	if req.Password == "" || req.Username == "" {
		return c.String(http.StatusBadRequest, "Username or Password is empty")
	}

	// データベースからユーザーを取得する
	user := User{}
	err = h.db.Get(&user, "SELECT * FROM users WHERE username=?", req.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.NoContent(http.StatusUnauthorized)
		} else {
			log.Println(err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}
	// パスワードが一致しているかを確かめる
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPass), []byte(req.Password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return c.NoContent(http.StatusUnauthorized)
		} else {
			return c.NoContent(http.StatusInternalServerError)
		}
	}
	// セッションストアに登録する
	sess, err := session.Get("sessions", c)
	if err != nil {
		log.Println(err)
		return c.String(http.StatusInternalServerError, "something wrong in getting session")
	}
	sess.Values["userName"] = req.Username
	sess.Save(c.Request(), c.Response())

	return c.NoContent(http.StatusOK)
}

func UserAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("sessions", c)
		if err != nil {
			log.Println(err)
			return c.String(http.StatusInternalServerError, "something wrong in getting session")
		}
		if sess.Values["userName"] == nil {
			return c.String(http.StatusUnauthorized, "please login")
		}
		c.Set("userName", sess.Values["userName"].(string))
		return next(c)
	}
}

type Me struct {
	Username string `json:"username,omitempty"  db:"username"`
}

func GetMeHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, Me{
		Username: c.Get("userName").(string),
	})
}

func (h *Handler) GetWorldHandler(c echo.Context) error {
	countryName := c.Param("countryName")
	cityName := c.Param("cityName")
	println("countryName : " + countryName)
	println("cityName : " + cityName)

	var howManyCountries = 0
	var country string
	var countries []string
	var countryCode string
	var howManyCities = 0
	var cities []string
	var city string
	var cityInfo City

	if countryName == "allCountries" {
		err := h.db.Get(&howManyCountries, "select count(*) from country")
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return c.NoContent(http.StatusNotFound)
			}
			log.Printf("failed to get world data 1 : %s\n", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		for i := 0; i < howManyCountries; i++ {
			err := h.db.Get(&country, "select Name from country order by Name asc limit 1 offset ?", i)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return c.NoContent(http.StatusNotFound)
				}
				log.Printf("failed to get world data 1 : %s\n", err)
				return c.NoContent(http.StatusInternalServerError)
			}
			countries = append(countries, country)
		}
		return c.JSON(http.StatusOK, countries)
	} else {
		if cityName == "allCities" {
			err := h.db.Get(&countryCode, "select Code from country where Name = ?", countryName)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return c.NoContent(http.StatusNotFound)
				}
				log.Printf("failed to get world data 2 : %s\n", err)
				return c.NoContent(http.StatusInternalServerError)
			} else {
				err := h.db.Get(&howManyCities, "select count(*) from city where CountryCode = ?", countryCode)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return c.NoContent(http.StatusNotFound)
					}
					log.Printf("failed to get world data here : %s\n", err)
					return c.NoContent(http.StatusInternalServerError)
				}
				for i := 0; i < howManyCities; i++ {
					err := h.db.Get(&city, "select Name from city where CountryCode = ? order by Name asc limit 1 offset ?", countryCode, i)
					if err != nil {
						if errors.Is(err, sql.ErrNoRows) {
							return c.NoContent(http.StatusNotFound)
						}
						log.Printf("failed to get world data 3 : %s\n", err)
						return c.NoContent(http.StatusInternalServerError)
					}
					cities = append(cities, city)
				}
				return c.JSON(http.StatusOK, cities)
			}
		} else {
			err := h.db.Get(&countryCode, "select Code from country where Name = ?", countryName)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return c.NoContent(http.StatusNotFound)
				}
				log.Printf("failed to get world data 4 : %s\n", err)
				return c.NoContent(http.StatusInternalServerError)
			} else {
				err := h.db.Get(&cityInfo, "select * from city where CountryCode = ? AND Name = ?", countryCode, cityName)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return c.NoContent(http.StatusNotFound)
					}
					log.Printf("failed to get world data 5 : %s\n", err)
					return c.NoContent(http.StatusInternalServerError)
				}
				return c.JSON(http.StatusOK, cityInfo)
			}
		}
	}
}
