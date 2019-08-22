node的web框架koa2+mongodb实现用户注册与登录验证（加密）过程
2019年01月15日 21:33:51 sleeppingforg 阅读数 329

本实例旨在演示node+koa2+mongodb一个简单的效果：

1 用户注册，（支持上传头像），保存用户信息至服务器（mongodb）

2 用户登录，如果用户输入密码和服务器加密后的密码一致，则返给客户端用户信息，否则返给客户端json，提示用户名或密码不正确

目录结构如下

koa（根目录）

    --------node_modules

    -------static //存放静态资源的目录

              ----------upload   //上传头像的目录

             -----------regist.html  //注册页面

             ------------login.html  //登录页面

    ------login.js              //登录逻辑的服务器文件

    ------regist.js              //注册逻辑的服务器文件

    --------dataBase.js     //处理数据库的文件

--------------------------------------------------------------------------------------------------------------------------

1存放在静态资源文件夹static下的两个页面

 regist.html

<form action="http://localhost:9999/addInfo" method="POST" enctype="multipart/form-data">

<p>姓名<input type="text" name="username" value=""></p>

<p>性别<input type="radio" name="gender" value="male"/>男<input type="radio" name="gender" value="female"/>女</p>

<p>密码<input type="password" name="password"></p>

<p><input type="file" name="file"></p>

<p><input type="submit"></p>

</form>

login.html

<form action="http://localhost:8989/login" method="POST" enctype="application/x-www-form-urlencoded">

<p><input type="text" name="username"></p>

<p><input type="password" name="password"></p>

<p><input type="submit" value="提交"></p>

</form>

 

2 位于根目录下的两个服务器文件regist.js、login.js

regist.js

var koa=require("koa");

var fs=require("fs");

var path=require("path")

var koaBody=require("koa-body");

var koaStatic=require("koa-static")

var router=require("koa-router")();

const baseUrl="http://localhost:9999";

var crypto=require("crypto");

 

//引入数据库配置文件

const dataBase=require('./dataBase.js');

var app=new koa();

 

//配置中间件

app.use(koaBody({

multipart:true,

formidable:{

uploadDir:path.join(__dirname,"static/upload"),

keepExtensions:true

}

}))

app.use(koaStatic(__dirname+"/static"));

app.use(router.routes())

app.use(router.allowedMethods());

 

//配置路由

router.get("/",async(ctx)=>{

let stream=fs.createReadStream("./static/submit.html");

ctx.type="html";

ctx.body=stream

})

router.post("/addInfo",async(ctx)=>{

let {username,password,gender}=ctx.request.body;

if(ctx.request.method!="get"){

let file=ctx.request.files.file;

let filePath=file.path;

let index=filePath.lastIndexOf("\\");

//写入数据到数据库,加密密码;

let md5=crypto.createHash("md5");

let newpass= md5.update(password).digest("hex");

let data={

username,

password:newpass,

gender,

url:baseUrl+`/upload/${filePath.substring(index+1)}`

}

let res= await dataBase.add(data);

//返回数据给客户端

ctx.body=data

}

})

app.listen(9999)

login.js

var fs=require("fs");

var koaBody=require("koa-body");

var koa=require("koa");

var router=require("koa-router")();

var crypto=require("crypto");

var dataBase=require("./dataBase.js");

var app=new koa();

app.use(koaBody());

app.use(router.routes());

app.use(router.allowedMethods());

 

router.get("/",async (ctx)=>{

ctx.type="html";

ctx.body=fs.createReadStream("./static/login.html");

})

 

router.post("/login",async (ctx)=>{

let {username,password}=ctx.request.body;

let md5=crypto.createHash("md5");

md5.update(password);

let passres=md5.digest("hex");

let newpass=passres

let resData=await dataBase.findOneUser({username:username});

if(resData.password==newpass){

ctx.body={

result:true,

data:{

username

}

}

}else{

ctx.body={

result:false,

data:{},

errInfo:"用户名或密码错误"

}

}

})

 

app.listen(8989)

 

最后一个配置服务器的baseData.js文件

baseData.js

var mongoose=require("mongoose");

const dbURL="mongodb://localhost:27017/user";

mongoose.connect(dbURL)

mongoose.connection.on("connected",()=>{console.log("连上"+dbURL)})

mongoose.connection.on("error",()=>{console.log("连结失败"+err)})

var schema=new mongoose.Schema({username:String,password:String,gender:String,url:String})

var userData=mongoose.model("userData",schema);;

 

class dataBaseHandle{

constructor(){

}

//添加

async add(data){

try{

       return await userData.create(data)

}catch(err){

      throw new Error(err)

}

}

async findOneUser(data){

  try {

         return await userData.findOne(data)

  } catch (error) {

      throw new Error(err)

 }

}

 

}

module.exports=new dataBaseHandle




返回主页	
Cedric's Blog

    博客园
    首页
    新随笔
    联系
    订阅
    管理

基于 Vue + Koa2 + MongoDB + Redis 实现一个完整的登录注册
项目地址：https://github.com/caochangkui/vue-element-responsive-demo/tree/login-register

通过 vue-cli3.0 + Element 构建项目前端，Node.js + Koa2 + MongoDB + Redis 实现数据库和接口设计，包括邮箱验证码、用户注册、用户登录、查看删除用户等功能。
1. 技术栈

    前端
        初始化项目：vue-cli3.0
        组件库：Element-ui
        路由控制/拦截：Vue-router
        状态管理：Vuex
    服务端
        运行环境：Node.js
        后台开发框架：Koa2
        路由中间件：Koa-router
        发送邮件: nodemailer
    HTTP通讯
        接口请求/拦截：Axios
        Token认证：jsonwebtoken
    数据库
        MongoDB
        数据库操作：Mongoose
        缓存工具：Redis

2. 项目依赖：

  "dependencies": { 
    "axios": "^0.18.0",
    "crypto-js": "^3.1.9-1", 
    "element-ui": "^2.4.5",
    "js-cookie": "^2.2.0",
    "jsonwebtoken": "^8.5.0", 
    "koa": "^2.7.0",
    "koa-bodyparser": "^4.2.1",
    "koa-generic-session": "^2.0.1",
    "koa-json": "^2.0.2",
    "koa-redis": "^3.1.3",
    "koa-router": "^7.4.0",
    "mongoose": "^5.4.19",
    "nodemailer": "^5.1.1",
    "nodemon": "^1.18.10", 
    "vue": "^2.5.21", 
    "vue-router": "^3.0.1",
    "vuex": "^3.0.1"
  }

3. 前端实现步骤
3.1 登录注册页面

通过 vue-cli3.0 + Element 构建项目前端页面
登录页（@/view/users/Login.vue）：

注册页（@/view/users/Register.vue）：

发送验证码前需要验证用户名和邮箱，用户名必填，邮箱格式需正确。

用户设置页（@/view/users/setting/Setting.vue）

用户登录后，可以进入用户设置页查看用户和删除用户
3.2 Vuex 状态管理

通过 vuex 实现保存或删除用户 token，保存用户名等功能。

由于使用单一状态树，应用的所有状态会集中到一个比较大的对象。当应用变得非常复杂时，store 对象就有可能变得相当臃肿。

为了解决以上问题，Vuex 允许我们将 store 分割成模块（module）。每个模块拥有自己的 state、mutation、action、getter。

根目录下新建store文件夹，创建modules/user.js:

const user = {
  state: {
    token: localStorage.getItem('token'),
    username: localStorage.getItem('username')
  },

  mutations: {
    BIND_LOGIN: (state, data) => {
      localStorage.setItem('token', data)
      state.token = data
    },
    BIND_LOGOUT: (state) => {
      localStorage.removeItem('token')
      state.token = null
    },
    SAVE_USER: (state, data) => {
      localStorage.setItem('username', data)
      state.username = data
    }
  }
}

export default user

创建文件 getters.js 对数据进行处理输出:

const getters = {
    sidebar: state => state.app.sidebar,
    device: state => state.app.device,
    token: state => state.user.token,
    username: state => state.user.username
  }
export default getters

创建文件 index.js 管理所有状态:

import Vue from 'vue'
import Vuex from 'vuex' 
import user from './modules/user'
import getters from './getters'

Vue.use(Vuex)

const store = new Vuex.Store({
  modules: { 
    user
  },
  getters
})

export default store

3.3 路由控制/拦截

路由配置（router.js）：

import Vue from 'vue'
import Router from 'vue-router' 
const Login = () => import(/* webpackChunkName: "users" */ '@/views/users/Login.vue')
const Register = () => import(/* webpackChunkName: "users" */ '@/views/users/Register.vue')  
const Setting = () => import(/* webpackChunkName: "tables" */ '@/views/setting/Setting.vue') 

Vue.use(Router)

const router = new Router({ 
  base: process.env.BASE_URL,
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: Login,
      meta: {
        title: '登录'
      }
    },
    {
      path: '/register',
      name: 'Register',
      component: Register,
      meta: {
        title: '注册'
      }
    },
    {
      path: '/setting',
      name: 'Setting',
      component: Setting,
      meta: {
        breadcrumb: '设置',
        requireLogin: true
      },
    }
  ]
})

路由拦截:

关于vue 路由拦截参考：https://www.cnblogs.com/cckui/p/10319013.html

// 页面刷新时，重新赋值token
if (localStorage.getItem('token')) {
  store.commit('BIND_LOGIN', localStorage.getItem('token'))
}

// 全局导航钩子
router.beforeEach((to, from, next) => {
  if (to.meta.title) { // 路由发生变化修改页面title
    document.title = to.meta.title
  }
  if (to.meta.requireLogin) {
    if (store.getters.token) {
      if (Object.keys(from.query).length === 0) { // 判断路由来源是否有query，处理不是目的跳转的情况
        next()
      } else {
          let redirect = from.query.redirect // 如果来源路由有query
          if (to.path === redirect) { // 避免 next 无限循环
              next()
          } else {
              next({ path: redirect }) // 跳转到目的路由
          }
      }
    } else {
      next({
        path: '/login',
        query: { redirect: to.fullPath } // 将跳转的路由path作为参数，登录成功后跳转到该路由
      })
    }
  } else {
    next()
  }
})

export default router

3.4 Axios 封装

封装 Axios

// axios 配置
import axios from 'axios'
import store from './store'
import router from './router'

//创建 axios 实例
let instance = axios.create({
  timeout: 5000, // 请求超过5秒即超时返回错误
  headers: { 'Content-Type': 'application/json;charset=UTF-8' },
})

instance.interceptors.request.use(
  config => {
    if (store.getters.token) { // 若存在token，则每个Http Header都加上token
      config.headers.Authorization = `token ${store.getters.token}`
      console.log('拿到token')
    }
    console.log('request请求配置', config)
    return config
  },
  err => {
    return Promise.reject(err)
  })

// http response 拦截器
instance.interceptors.response.use(
  response => {
    console.log('成功响应：', response)
    return response
  },
  error => {
    if (error.response) {
      switch (error.response.status) {
        case 401:
          // 返回 401 (未授权) 清除 token 并跳转到登录页面
          store.commit('BIND_LOGOUT')
          router.replace({
            path: '/login',
            query: {
              redirect: router.currentRoute.fullPath
            }
          })
          break
        default:
          console.log('服务器出错，请稍后重试！')
          alert('服务器出错，请稍后重试！')
      }
    }
    return Promise.reject(error.response) // 返回接口返回的错误信息
  }
)

export default {
  // 发送验证码
  userVerify (data) {
    return instance.post('/api/verify', data)
  },
  // 注册
  userRegister (data) {
    return instance.post('/api/register', data)
  },
  // 登录
  userLogin (data) {
    return instance.post('/api/login', data)
  },
  // 获取用户列表
  getAllUser () {
    return instance.get('/api/alluser')
  },
  // 删除用户
  delUser (data) {
    return instance.post('/api/deluser', data)
  }
}

4. 服务端和数据库实现

在根目录下创建 server 文件夹，存放服务端和数据库相关代码。
4.1 MongoDB和Redis

创建 /server/dbs/config.js ，进行数据库和邮箱配置

// mongo 连接地址
const dbs = 'mongodb://127.0.0.1:27017/[数据库名称]'

// redis 地址和端口
const redis = {
  get host() {  
    return '127.0.0.1'
  },
  get port() {
    return 6379
  }
}

// qq邮箱配置
const smtp = {
  get host() {
    return 'smtp.qq.com'
  },
  get user() {
    return '1********@qq.com' // qq邮箱名
  },
  get pass() {
    return '*****************' // qq邮箱授权码
  },
  // 生成邮箱验证码
  get code() {
    return () => {
      return Math.random()
        .toString(16)
        .slice(2, 6)
        .toUpperCase()
    }
  },
  // 定义验证码过期时间rules，5分钟
  get expire() {
    return () => {
      return new Date().getTime() + 5 * 60 * 1000
    }
  }
}

module.exports = {
  dbs,
  redis,
  smtp
}

使用 qq 邮箱发送验证码，需要在“设置/账户”中打开POP3/SMTP服务和MAP/SMTP服务。
4.2 Mongo 模型

创建 /server/dbs/models/users.js:

// users模型，包括四个字段
const mongoose = require('mongoose')
const Schema = mongoose.Schema
const UserSchema = new Schema({
  username: {
    type: String,
    unique: true,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  token: {
    type: String,
    required: true
  }
})

module.exports = {
  Users: mongoose.model('User', UserSchema)
}

4.3 接口实现

创建 /server/interface/user.js:

const Router = require('koa-router')
const Redis = require('koa-redis') // key-value存储系统, 存储用户名，验证每个用户名对应的验证码是否正确
const nodeMailer = require('nodemailer') // 通过node发送邮件
const User = require('../dbs/models/users').Users
const Email = require('../dbs/config')

// 创建和验证token, 参考4.4
const createToken = require('../token/createToken.js') // 创建token
const checkToken = require('../token/checkToken.js') // 验证token


// 创建路由对象
const router = new Router({
  prefix: '/api' // 接口的统一前缀
})

// 获取redis的客户端
const Store = new Redis().client

// 接口 - 测试
router.get('/test', async ctx => {
  ctx.body = {
    code: 0,
    msg: '测试',
  }
})

// 发送验证码 的接口
router.post('/verify', async (ctx, next) => {
  const username = ctx.request.body.username
  const saveExpire = await Store.hget(`nodemail:${username}`, 'expire') // 拿到过期时间

  console.log(ctx.request.body)
  console.log('当前时间:', new Date().getTime())
  console.log('过期时间：', saveExpire)

  // 检验已存在的验证码是否过期，以限制用户频繁发送验证码
  if (saveExpire && new Date().getTime() - saveExpire < 0) {
    ctx.body = {
      code: -1,
      msg: '发送过于频繁，请稍后再试'
    }
    return
  }

  // QQ邮箱smtp服务权限校验
  const transporter = nodeMailer.createTransport({
    /**
     *  端口465和587用于电子邮件客户端到电子邮件服务器通信 - 发送电子邮件。
     *  端口465用于smtps SSL加密在任何SMTP级别通信之前自动启动。
     *  端口587用于msa
     */
    host: Email.smtp.host,
    port: 587,
    secure: false, // 为true时监听465端口，为false时监听其他端口
    auth: {
      user: Email.smtp.user,
      pass: Email.smtp.pass
    }
  })

  // 邮箱需要接收的信息
  const ko = {
    code: Email.smtp.code(),
    expire: Email.smtp.expire(),
    email: ctx.request.body.email,
    user: ctx.request.body.username
  }

  // 邮件中需要显示的内容
  const mailOptions = {
    from: `"认证邮件" <${Email.smtp.user}>`, // 邮件来自
    to: ko.email, // 邮件发往
    subject: '邀请码', // 邮件主题 标题
    html: `您正在注册****，您的邀请码是${ko.code}` // 邮件内容
  }

  // 执行发送邮件
  await transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      return console.log('error')
    } else {
      Store.hmset(`nodemail:${ko.user}`, 'code', ko.code, 'expire', ko.expire, 'email', ko.email)
    }
  })

  ctx.body = {
    code: 0,
    msg: '验证码已发送，请注意查收，可能会有延时，有效期5分钟'
  }
})

// 接口 - 注册
router.post('/register', async ctx => {
  const { username, password, email, code } = ctx.request.body

  // 验证验证码
  if (code) {
    const saveCode = await Store.hget(`nodemail:${username}`, 'code') // 拿到已存储的真实的验证码
    const saveExpire = await Store.hget(`nodemail:${username}`, 'expire') // 过期时间

    console.log(ctx.request.body)
    console.log('redis中保存的验证码：', saveCode)
    console.log('当前时间:', new Date().getTime())
    console.log('过期时间：', saveExpire)

    // 用户提交的验证码是否等于已存的验证码
    if (code === saveCode) {
      if (new Date().getTime() - saveExpire > 0) {
        ctx.body = {
          code: -1,
          msg: '验证码已过期，请重新申请'
        }
        return
      }
    } else {
      ctx.body = {
        code: -1,
        msg: '请填写正确的验证码'
      }
      return
    }
  } else {
    ctx.body = {
      code: -1,
      msg: '请填写验证码'
    }
    return
  }

  // 用户名是否已经被注册
  const user = await User.find({ username })
  if (user.length) {
    ctx.body = {
      code: -1,
      msg: '该用户名已被注册'
    }
    return
  }
  // 如果用户名未被注册，则写入数据库
  const newUser = await User.create({
    username,
    password,
    email,
    token: createToken(this.username) // 生成一个token 存入数据库
  })

  // 如果用户名被成功写入数据库，则返回注册成功
  if (newUser) {
    ctx.body = {
      code: 0,
      msg: '注册成功',
    }
  } else {
    ctx.body = {
      code: -1,
      msg: '注册失败'
    }
  }
})


// 接口 - 登录
router.post('/login', async (ctx, next) => {
  const { username, password } = ctx.request.body

  let doc = await User.findOne({ username })
  if (!doc) { 
    ctx.body = {
      code: -1,
      msg: '用户名不存在'
    }
  } else if (doc.password !== password) {
    ctx.body = {
      code: -1,
      msg: '密码错误'
    }
  } else if (doc.password === password) {
    console.log('密码正确')
    let token = createToken(username) // 生成token 
    doc.token = token // 更新mongo中对应用户名的token
    try {
      await doc.save() // 更新mongo中对应用户名的token
      ctx.body = {
        code: 0,
        msg: '登录成功',
        username,
        token
      }
    } catch (err) {
      ctx.body = {
        code: -1,
        msg: '登录失败，请重新登录'
      }
    }
  }
})

// 接口 - 获取所有用户 需要验证 token
router.get('/alluser', checkToken, async (ctx, next) => {
  try {
    let result = []
    let doc = await User.find({}) 
    doc.map((val, index) => {
      result.push({
        email: val.email,
        username: val.username,
      })
    }) 
    ctx.body = {
      code: 0,
      msg: '查找成功',
      result
    }
  } catch (err) {
    ctx.body = {
      code: -1,
      msg: '查找失败',
      result: err
    }
  }
})

// 接口 - 删除用户 需要验证 token
router.post('/deluser', checkToken, async (ctx, next) => {
  const { username } = ctx.request.body

  try {
    await User.findOneAndRemove({username: username})
    ctx.body = {
      code: 0,
      msg: '删除成功',
    }
  } catch (err) {
    ctx.body = {
      code: -1,
      msg: '删除失败',
    }
  }
})

module.exports = {
  router
}

上面实现了五个接口：

    发送验证码至邮箱： router.post('/verify')
    注册：router.post('/register')
    登录：router.post('/login')
    获取用户列表：router.get('/alluser')
    删除数据库中的某个用户：router.post('/deluser')

分别对应了前面 3.4 中 axios 中的5个请求地址
4.4 JSON Web Token 认证

JSON Web Token（缩写 JWT）是目前最流行的跨域认证解决方案。详情参考：http://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html

分别创建 /server/token/createToken.js 和 /server/token/checkToken.js

// 创建token
const jwt = require('jsonwebtoken') 

module.exports = function (id) {
  const token = jwt.sign(
    {
      id: id
    },
    'cedric1990',
    {
      expiresIn: '300s'
    }
  )

  return token
}

// 验证token
const jwt = require('jsonwebtoken')

// 检查 token
module.exports = async (ctx, next) => {
  // 检验是否存在 token
  // axios.js 中设置了 authorization
  const authorization = ctx.get('Authorization')
  if (authorization === '') {
    ctx.throw(401, 'no token detected in http headerAuthorization')
  }

  const token = authorization.split(' ')[1]

  // 检验 token 是否已过期
  try {
    await jwt.verify(token, 'cedric1990')
  } catch (err) {
    ctx.throw(401, 'invalid token')
  }

  await next()
}

4.5 服务端入口

根目录创建 server.js:

// server端启动入口
const Koa = require('koa')
const app =  new Koa();
const mongoose = require('mongoose')
const bodyParser = require('koa-bodyparser')
const session = require('koa-generic-session')
const Redis = require('koa-redis')
const json = require('koa-json') // 美化json格式化
const dbConfig = require('./server/dbs/config')

const users = require('./server/interface/user.js').router

// 一些session和redis相关配置
app.keys = ['keys', 'keyskeys']
app.proxy = true
app.use(
  session({ 
    store: new Redis()
  })
)

app.use(bodyParser({
  extendTypes: ['json', 'form', 'text']
}))

app.use(json())

// 连接数据库
mongoose.connect(
  dbConfig.dbs,
  { useNewUrlParser: true }
)

mongoose.set('useNewUrlParser', true)
mongoose.set('useFindAndModify', false)
mongoose.set('useCreateIndex', true)

const db = mongoose.connection
mongoose.Promise = global.Promise // 防止Mongoose: mpromise 错误

db.on('error', function () {
    console.log('数据库连接出错')
})

db.on('open', function () {
    console.log('数据库连接成功')
})

// 路由中间件
app.use(users.routes()).use(users.allowedMethods())

app.listen(8888, () => {
  console.log('This server is running at http://localhost:' + 8888)
})

5. 跨域处理

详情参考:https://www.cnblogs.com/cckui/p/10331432.html

vue 前端启动端口9527 和 koa 服务端启动端口8888不同，需要做跨域处理，打开vue.config.js:

devServer: {
    port: 9527,
    https: false,
    hotOnly: false,
    proxy: { 
      '/api': {
        target: 'http://127.0.0.1:8888/', // 接口地址
        changeOrigin: true,
        ws: true,
        pathRewrite: {
          '^/': ''
        }
      }
    }
  }

6. 接口对接

import axios from '../../axios.js'
import CryptoJS from 'crypto-js' // 用于MD5加密处理

发送验证码：

// 用户名不能为空，并且验证邮箱格式
sendCode() {
  let email = this.ruleForm2.email
  if (this.checkEmail(email) && this.ruleForm2.username) {  
    axios.userVerify({
      username: encodeURIComponent(this.ruleForm2.username),
      email: this.ruleForm2.email
    }).then((res) => {
      if (res.status === 200 && res.data && res.data.code === 0) {
        this.$notify({
          title: '成功',
          message: '验证码发送成功，请注意查收。有效期5分钟',
          duration: 1000,
          type: 'success'
        })

        let time = 300
        this.buttonText = '已发送'
        this.isDisabled = true
        if (this.flag) {
          this.flag = false;
          let timer = setInterval(() => {
            time--;
            this.buttonText = time + ' 秒'
            if (time === 0) {
              clearInterval(timer);
              this.buttonText = '重新获取'
              this.isDisabled = false
              this.flag = true;
            }
          }, 1000)
        }
      } else {
        this.$notify({
          title: '失败',
          message: res.data.msg,
          duration: 1000,
          type: 'error'
        })
      }
    })
  }
}

注册:

submitForm(formName) {
  this.$refs[formName].validate(valid => {
    if (valid) {
      axios.userRegister({
        username: encodeURIComponent(this.ruleForm2.username),
        password: CryptoJS.MD5(this.ruleForm2.pass).toString(),
        email: this.ruleForm2.email,
        code: this.ruleForm2.smscode
      }).then((res) => {
        if (res.status === 200) {
          if (res.data && res.data.code === 0) {
            this.$notify({
              title: '成功',
              message: '注册成功。',
              duration: 2000,
              type: 'success'
            })
            setTimeout(() => {
              this.$router.push({
                path: '/login'
              })
            }, 500)
          } else {
            this.$notify({
              title: '错误',
              message: res.data.msg,
              duration: 2000,
              type: 'error'
            })
          }
        } else {
          this.$notify({
            title: '错误',
            message: `服务器请求出错， 错误码${res.status}`,
            duration: 2000,
            type: 'error'
          })
        }
      }) 
    } else {
      console.log("error submit!!");
      return false;
    }
  })
},

登录：

login(formName) {
  this.$refs[formName].validate(valid => {
    if (valid) { 
      axios.userLogin({
        username: window.encodeURIComponent(this.ruleForm.name),
        password: CryptoJS.MD5(this.ruleForm.pass).toString()
      }).then((res) => { 
        if (res.status === 200) {
          if (res.data && res.data.code === 0) {
            this.bindLogin(res.data.token)
            this.saveUser(res.data.username)
            this.$notify({
              title: '成功',
              message: '恭喜，登录成功。',
              duration: 1000,
              type: 'success'
            })
            setTimeout(() => {
              this.$router.push({
                path: '/'
              })
            }, 500)
          } else {
            this.$notify({
              title: '错误',
              message: res.data.msg,
              duration: 1000,
              type: 'error'
            })
          }
        } else {
          this.$notify({
            title: '错误',
            message: '服务器出错，请稍后重试',
            duration: 1000,
            type: 'error'
          })
        }
      })
    }
  })
},

7. 启动项目 测试接口
7.1 vue端：

$ npm run serve

7.2 启动mogod：

$ mongod

7.3 启动Redis：

$ redis-server

7.4 启动服务端server.js：

安装 nodemon 热启动辅助工具：

$ npm i nodemon

$ nodemon server.js

8. 项目目录

分类: mongoDB,Vue.js,ES7,koa2,ES6,JavaScript,mongoose,Redis,Node.js
标签: mongoDB, mongoose, koa2, Node.js, ES6, vue, element, redis, session, token
好文要顶 关注我 收藏该文
Mr.曹
关注 - 22
粉丝 - 19
+加关注
0
0
« 上一篇：vue 项目中添加阿里巴巴矢量图
» 下一篇：koa2 中使用 svg-captcha 生成验证码
posted @ 2019-03-17 12:35 Mr.曹 阅读(476) 评论(0) 编辑 收藏
刷新评论刷新页面返回顶部
注册用户登录后才能发表评论，请 登录 或 注册，访问网站首页。
相关博文：
· vue2.0+koa2+mongodb实现注册登录
· Vuenodejs商城项目-登录模块
· vue+Mint-ui实现登录注册
· vue+vuex+axios实现登录、注册页权限拦截
· koa+mysql+vue+socket.io全栈开发之webapi篇
最新新闻：
· 欧洲伽利略导航系统服务中断
· 大众与福特拓展全球联盟 将向电动车及自动驾驶投入26亿美元
· 超级大脑“暴走”BAT
· Golang 到底姓什么？开发者想移除谷歌 logo
· 情怀没了：微软关闭Windows内置休闲游戏
» 更多新闻...
公告
[访问github]
小程序
MongoDB
Python/Django
Webpack
MySQL
React
Vue/Nuxt
ES6/ES7
Node/Koa2

小程序扫码预览
昵称：Mr.曹
园龄：1年10个月
粉丝：19
关注：22
+加关注
<	2019年7月	>
日	一	二	三	四	五	六
30	1	2	3	4	5	6
7	8	9	10	11	12	13
14	15	16	17	18	19	20
21	22	23	24	25	26	27
28	29	30	31	1	2	3
4	5	6	7	8	9	10
搜索
 
 
最新随笔

    1. 垃圾分类小程序 6000多种垃圾一键可查（可回收物、有害垃圾、干垃圾、湿垃圾、厨余垃圾、易腐垃圾）
    2. 一些常用的 Emoji 符号（可直接复制）
    3. 基于 express + mysql + redis 搭建多用户博客系统
    4. PM2 对 Node 项目进行线上部署与配置
    5. Koa2 和 Express 中间件对比

我的标签

    JavaScript(44)Node.js(23)ES6(22)vue(19)移动端(16)微信小程序(15)CSS 3(11)koa2(9)Vue 2.0实例(9)Promise(7)更多 

随笔分类(236)

    CSS3(20) Django(1) ES6(21) ES7(10) Express(2) Gulp(1) HTML(13) JavaScript(53) jQuery(1) koa2(9) mongoDB(3) mongoose(1) Mysql(4) Nginx(1) Node.js(24) Nuxt.js(2) PHP(1) Python(1) React.js Redis(3) Vue.js(22) 上线与部署(2) 网络安全(2) 小程序(15) 移动端(19) 杂记(5) 

随笔档案(108)

    2019年6月 (9) 2019年5月 (5) 2019年4月 (6) 2019年3月 (4) 2019年2月 (7) 2019年1月 (16) 2018年12月 (6) 2018年11月 (25) 2018年8月 (5) 2018年7月 (2) 2018年1月 (5) 2017年12月 (3) 2017年11月 (1) 2017年10月 (3) 2017年9月 (8) 2017年8月 (3) 

友情链接

    Awesomes 伯乐在线 奇舞周刊 前端代码规范 印记中文 

阅读排行榜

    1. PHP+Mysql 实现数据库增删改查(30576)
    2. 基于Vue.js 2.0 + Vuex打造微信项目(6944)
    3. vue 中使用 async/await 将 axios 异步请求同步化处理(6850)
    4. vue-cli 3.0 图片路径问题（何时使用 public 文件夹）(5869)
    5. ES6 之reduce的高级技巧(5745)

评论排行榜

    1. 垃圾分类小程序 6000多种垃圾一键可查（可回收物、有害垃圾、干垃圾、湿垃圾、厨余垃圾、易腐垃圾）(3)
    2. PHP+Mysql 实现数据库增删改查(2)
    3. vue-cli 3.0 axios 跨域请求代理配置及生产环境 baseUrl 配置(2)
    4. 基于Vue.js 2.0 + Vuex打造微信项目(1)
    5. JavaScript实现选项卡（三种方法）(1)

推荐排行榜

    1. PHP+Mysql 实现数据库增删改查(2)
    2. HTML5 之 FileReader 方法上传并读取文件(1)
    3. 垃圾分类小程序 6000多种垃圾一键可查（可回收物、有害垃圾、干垃圾、湿垃圾、厨余垃圾、易腐垃圾）(1)

Copyright ©2019 Mr.曹
