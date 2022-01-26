import express from 'express';
import cookieParser from "cookie-parser";
import cors from 'cors';
import {createConnection} from "typeorm";
import {routes} from "./routes";

createConnection().then(() => {
    const app = express();

    app.use(express.json());
    app.use(cookieParser());
    app.use(cors({
        origin: ['http://localhost:3000', 'http://localhost:8080', 'http://localhost:4200'],
        credentials: true
    }));

    routes(app);

    app.listen(8000, () => {
        console.log('listening to port 8000')
    });
})

