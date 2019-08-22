/* eslint-disable new-cap */
const koa = require('koa')
// const router = require('koa-router') ()
const router = require('./routes')

// const config = require ('./config')
// const controllers = require('./controllers')

// router.get('/', async (ctx, next) => {
//      ctx.body = '这是后台首页'
//      if(1 === 1){
//         controllers.admin
//      }
//   })

// router.get('/', async (ctx, next) => {
//   await ctx.render('index', {
//     title: 'Hello Koa 2!'
//   })
// })

const { connect } = require('./database/init')
;(async () => {
  await connect()
})()

const app = new koa()
app.use(router.routes())

app.listen(6677, () => { console.log('端口为6677的服务器启动了！') })
