// require('dotenv').config({ path: './env' })
// import mongoose from "mongoose";
// import { DB_NAME } from "./constants";

import dotenv from 'dotenv'
import connectDB from './db/index.js'
import { app } from './app.js'

dotenv.config({
    path: './env'
})

connectDB()
    .then(() => {
        app.listen(process.env.PORT || 8000, () => {
            console.log(`server is runinging at port http://localhost:${process.env.PORT}/`)
        })
        app.on('error', (err) => {
            console.log('Err: ', err)
        })
    })
    .catch((err) => { console.log('MONGO db connection failed !!!', err) })

/*import express from 'express'


const app = express()

    (async () => {
        try {
            await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)

            express.on('error', (error) => {
                console.error("ERROR: ", error)
            })

            app.listen(process.env.PORT, () => {
                console.log(`App is listening on port ${process.env.PORT}`)
            })
        } catch (error) {
            console.error("ERROR:", error)
            throw error
        }
    })()*/


