const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const pool = require('./db')

const app = express()

const cors = require('cors')

app.use(cors({
  origin: '*',
  credentials: true
}))

app.use(express.json())



const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET

function auth(req, res, next) {
  const token = req.headers.authorization

  if (!token) {
    return res.status(401).json({
      error: 'Нет токена'
    })
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET)

    req.user = decoded

    next()
  } catch {
    res.status(401).json({
      error: 'Неверный токен'
    })
  }
}

app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body

    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        error: 'Пользователь уже существует'
      })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const result = await pool.query(
      `
      INSERT INTO users (email, password)
      VALUES ($1, $2)
      RETURNING id, email
    `,
      [email, hashedPassword]
    )

    const user = result.rows[0]

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      JWT_SECRET,
      {
        expiresIn: '7d'
      }
    )

    res.json({ token })
  } catch (error) {
    console.log(error)

    res.status(500).json({
      error: 'Ошибка сервера'
    })
  }
})

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )

    if (result.rows.length === 0) {
      return res.status(400).json({
        error: 'Пользователь не найден'
      })
    }

    const user = result.rows[0]

    const validPassword = await bcrypt.compare(
      password,
      user.password
    )

    if (!validPassword) {
      return res.status(400).json({
        error: 'Неверный пароль'
      })
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      JWT_SECRET,
      {
        expiresIn: '7d'
      }
    )

    res.json({ token })
  } catch (error) {
    console.log(error)

    res.status(500).json({
      error: 'Ошибка сервера'
    })
  }
})

app.get('/foods', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM foods ORDER BY name'
    )

    res.json(result.rows)
  } catch (error) {
    console.log(error)

    res.status(500).json({
      error: 'Ошибка сервера'
    })
  }
})

app.get('/meals', auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        meals.id,
        meals.grams,
        foods.name,
        foods.calories,
        foods.proteins,
        foods.fats,
        foods.carbs
      FROM meals
      JOIN foods
      ON meals.food_id = foods.id
      WHERE meals.user_id = $1
      ORDER BY meals.id DESC
    `,
      [req.user.id]
    )

    const meals = result.rows.map(meal => ({
      id: meal.id,
      name: meal.name,
      grams: meal.grams,
      calories: (
        meal.calories * meal.grams / 100
      ).toFixed(1),

      proteins: (
        meal.proteins * meal.grams / 100
      ).toFixed(1),

      fats: (
        meal.fats * meal.grams / 100
      ).toFixed(1),

      carbs: (
        meal.carbs * meal.grams / 100
      ).toFixed(1),
    }))

    res.json(meals)
  } catch (error) {
    console.log(error)

    res.status(500).json({
      error: 'Ошибка сервера'
    })
  }
})

app.post('/meals', auth, async (req, res) => {
  try {
    const { food_id, grams } = req.body

    await pool.query(
      `
      INSERT INTO meals (food_id, grams, user_id)
      VALUES ($1, $2, $3)
    `,
      [food_id, grams, req.user.id]
    )

    res.json({
      message: 'Добавлено'
    })
  } catch (error) {
    console.log(error)

    res.status(500).json({
      error: 'Ошибка сервера'
    })
  }
})

app.delete('/meals/:id', auth, async (req, res) => {
  try {
    const { id } = req.params

    await pool.query(
      `
      DELETE FROM meals
      WHERE id = $1
      AND user_id = $2
    `,
      [id, req.user.id]
    )

    res.json({
      message: 'Удалено'
    })
  } catch (error) {
    console.log(error)

    res.status(500).json({
      error: 'Ошибка сервера'
    })
  }
})

app.listen(PORT, () => {
  console.log(`Server started on ${PORT}`)
})