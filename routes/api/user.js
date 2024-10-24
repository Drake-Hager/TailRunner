import express from 'express';
import debug from 'debug';
const debugUser = debug('app:User')
import Joi from 'joi';
import {validBody} from '../../middleware/validBody.js';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
const router = express.Router();

const newUserSchema = Joi.object({
  email: Joi.string().email().required(), 
  password: Joi.string().min(5).required()
})

async function issueAuthToken(user){
  const token = jwt.sign({_id:user._id},{email:user.email}, process.env.JWT_SECRET, {expiresIn: '1h'})
  return token;
}

router.get('/', (req, res)=>{
  res.json('Get all users route hit')
});

router.post('/register', validBody(newUserSchema),async (req, res)=>{
  const user = req.body;
  const existingUser = await getUserByEmail(user.email);
  if(existingUser){
    return res.status(400).json('User email already exists')
  }else{
    user.password = await bcrypt.hash(user.password, 10)
  }
  
  res.json('Register User Route hit')
})

export {router as userRouter}