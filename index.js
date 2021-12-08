const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')

dotenv.config()

// db
const db = require('./db')

// routes
const routes = require('./router')

const app = express()
app.disable('x-powered-by');


const PORT = process.env.PORT || 5000

var corsOptions = {
  origin: 'https://demo.authmosis.com',
  optionsSuccessStatus: 204 // some legacy browsers (IE11, various SmartTVs) choke on 204
}

app.use(cors(corsOptions))
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

// adding routes with controllers
app.use(routes)

db.connect().then(() => {
  console.log('Connected to DB')
  app.listen(PORT, () => console.log(`Server running on PORT ${PORT}`))
})
