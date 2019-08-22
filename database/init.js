const mongoose = require('mongoose')
const db = 'mongodb://localhost:27020/koa_db'
mongoose.Promise = global.Promise

exports.connect = () => {
  // eslint-disable-next-line no-unused-vars
  let maxConnectTime = 0
  return new Promise((resolve, reject) => {
    if (process.env.NODE_ENV !== 'production') {
      mongoose.set('debug', true)
    }
    mongoose.connect(db) // 连接数据库
    mongoose.connection.on('disconnected', () => { // 当数据库断开时，重新连接数据库
      maxConnectTime++
      if (maxConnectTime < 5) {
        mongoose.connect(db)
      } else {
        throw new Error('数据库连接失败！')
      }
    })

    mongoose.connection.on('error', err => { // 当数据库连接错误时，
      reject(err)
      console.log(err)
    })
    mongoose.connection.once('open', () => { // 当大数据库连接成功时
      resolve()
      console.log('MongoDB Connected successfully!')
    })
  })
}
