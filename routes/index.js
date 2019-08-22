/**
 * ajax 服务路由集合
 */
const router = require('koa-router')({
  prefix: '/weapp'
})

// xxx.com/weapp/demo  --->>访问微信小程序后台，正确的网址书写
const controllers = require('../controllers')

// 客户登录路由
// router.post('/denglu', controllers.admin)
// router.get('/a', controllers.admin)

router.get('/', async (ctx, next) => {
  let a = 1
  let b = 2
  if (a + b === 3) {
    console.log('这是这里是路由控制条件')
    next()
  } else {
    console.log('对不起，您不符合条件，无法开放路由！')
  }
},
controllers.admin
)

// router.post('/register', async (ctx, next) => {

// }, controllers.register)
 //  router.post('/register',  controllers.register)
// router.post('/upload', controllers.upload)

router.post('/register', async (ctx, next) => {
  let a = 1
  let b = 2
  if (a + b === 3) {
    console.log('这是这里是路由控制条件')
    next()
  } else {
    console.log('对不起，您不符合条件，无法开放路由！')
  }
},
controllers.register
)


module.exports = router
