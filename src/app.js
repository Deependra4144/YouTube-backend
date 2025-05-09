import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'

const app = express()

app.use(cors({
    origin: process.env.CORSE_ORIGIN,
    credentials: true
}))

app.use(express.json({ limit: '20kb' }))
app.use(express.urlencoded({ extended: true, limit: '20kb' }))
// app.use(express.static('public'))
app.use(cookieParser())


// routes
import userRouter from './routes/user.routes.js'


// routes declaration
app.use('/api/v1/users', userRouter)

// app.post("/api/v1/users/register", (req, res, next) => {
//     res.status(200).json({
//         message: "all good"
//     })
// })

// http://localhost:8000/api/v1/user/x...
export { app }