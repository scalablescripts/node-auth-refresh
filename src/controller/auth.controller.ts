import {Request, Response} from "express";
import {getRepository, MoreThanOrEqual} from "typeorm";
import {User} from "../entity/user.entity";
import bcryptjs from 'bcryptjs';
import {sign, verify} from 'jsonwebtoken';
import {Token} from "../entity/token.entity";

export const Register = async (req: Request, res: Response) => {
    const {name, email, password} = req.body;

    const user = await getRepository(User).save({
        name,
        email,
        password: await bcryptjs.hash(password, 12)
    });

    res.send(user);
}

export const Login = async (req: Request, res: Response) => {
    const {email, password} = req.body;

    const user = await getRepository(User).findOne({email});

    if (!user) {
        return res.status(400).send({
            message: 'Invalid credentials'
        })
    }

    if (!await bcryptjs.compare(password, user.password)) {
        return res.status(400).send({
            message: 'Invalid credentials'
        })
    }

    const refreshToken = sign({
        id: user.id
    }, "refresh_secret", {expiresIn: '1w'});

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000 //7 days
    });

    const expired_at = new Date();
    expired_at.setDate(expired_at.getDate() + 7);

    await getRepository(Token).save({
        user_id: user.id,
        token: refreshToken,
        expired_at
    });

    const token = sign({
        id: user.id
    }, "access_secret", {expiresIn: '30s'});

    res.send({
        token
    });
}

export const AuthenticatedUser = async (req: Request, res: Response) => {
    try {
        const accessToken = req.header('Authorization')?.split(" ")[1] || "";

        const payload: any = verify(accessToken, "access_secret");

        if (!payload) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const user = await getRepository(User).findOne(payload.id);

        if (!user) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const {password, ...data} = user;

        res.send(data);
    } catch (e) {
        return res.status(401).send({
            message: 'unauthenticated'
        });
    }
}

export const Refresh = async (req: Request, res: Response) => {
    try {
        const refreshToken = req.cookies['refreshToken'];

        const payload: any = verify(refreshToken, "refresh_secret");

        if (!payload) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const dbToken = await getRepository(Token).findOne({
            user_id: payload.id,
            expired_at: MoreThanOrEqual(new Date())
        });

        if (!dbToken) {
            return res.status(401).send({
                message: 'unauthenticated'
            });
        }

        const token = sign({
            id: payload.id
        }, "access_secret", {expiresIn: '30s'});

        res.send({
            token
        })
    } catch (e) {
        return res.status(401).send({
            message: 'unauthenticated'
        });
    }
}

export const Logout = async (req: Request, res: Response) => {
    const refreshToken = req.cookies['refreshToken'];

    await getRepository(Token).delete({token: refreshToken});

    res.cookie('refreshToken', '', {maxAge: 0});

    res.send({
        message: 'success'
    });
}
