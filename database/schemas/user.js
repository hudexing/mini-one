const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const Schema = mongoose.Schema
// const Mixed = Schema.Types.Mixed // 可以存放任何类型的数据，适合数据类型变化频繁的场景，是mongodb特有的
const SALT_WORK_FACTOR = 10 // 加的盐值
const MAX_LOGIN_ATTEMPTS = 5 // 最多登录次数
const LOCK_TIME = 2 * 60 * 60 * 1000 // 登录错误时的锁定时间，单位毫秒

const userSchema = new Schema({
  username: {
    unique: true, // 在数据库中设置名字为唯一的,不允许有重复的数据出现。
    type: String, // 字符类型为string即字符串类型
    required: true // 此字段不能为空
  },
  email: {
    unique: true,
    type: String,
    required: true // 此字段不能为空
  },
  password: {
    unique: true,
    type: String
  },
  // 虚拟字段，不会被存储到数据库里面，而是每一次通过get方法来判断
  loginAttempts: { // 用户登录的次数
    type: Number, // 值得类型
    required: true, // 此类型的值不能为空
    default: 0 // 默认值或初始值为0
  },
  lockUntil: Number, // 表示的是毫秒值，用户账号异常时锁定的时间
  mate: {
    createdAt: {
      type: Date,
      default: Date.now()
    },
    updatedAt: {
      type: Date,
      default: Date.now()
    }
  }
})

userSchema.virtual('isLocked').get(() => { // 虚拟字段，不会被
// 存储到数据库里面，而是每一次通过get方法来判断
  return !!(this.lockUntil && this.lockUntil > Date.now())
})

userSchema.pre('save', next => {
  if (!this.isModified('password')) return next() // 通过modified判断密码是否更改

  // eslint-disable-next-line no-undef
  bcrypt.genSalt(SALT_WORK_FACTOR, (err, salt) => {
    if (err) return next(err) // 如果在构建盐的过程出错，把错误往下传
    // 如果没有构建盐的过程中没有错误，
    // eslint-disable-next-line no-undef
    bcrypt.hash(this.password, salt, (error, hash) => {
      if (error) return next(error)

      this.password = hash
      next()
    })
  })

  if (this.isNew) { // 更新创建时间、更新时间
    this.mate.createdAt = this.mate.updatedAt = Date.now()
  } else {
    this.mate.updatedAt = Date.now()
  }
  next()
})

userSchema.methods = { // 实例方法
  comparePassword: (_password, password) => { // 比较密码
    // _password是前端明文传过来的密码，password是数据库存储的密码、加盐加密后的密码
    return new Promise((resolve, reject) => { // 包装成promise进行密码比对
      // 通过bcrypt下面的compare方法进行比较
      bcrypt.compare(_password, password, (err, isMatch) => { // isMatch即true
        if (!err) resolve(isMatch)
        else reject(err)
      })
    })
  },

  incLoginAttepts: (user) => { // 判断用户是不是超过登录次数、进行锁定
    return new Promise((resolve, reject) => {
      // 如果现在已经锁定了，并且已经过了锁定的时间
      if (this.lockUntil && this.lockUntil < Date.now()) {
        this.update({
          $set: {
            loginAttempts: 1 // 设置为登录次数为1次
          },
          $unset: {
            lockUntil: 1 // 设置为最小值1毫秒
          }
        }, (err) => {
          if (!err) resolve(true)
          else reject(err)
        })
      } else {
        let updates = {
          $inc: {
            loginAttempts: 1
          }
        }
        if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
          updates.$set = {
            lockUntil: Date.now() + LOCK_TIME
          }
        }
        this.update(updates, err => {
          if (!err) resolve(true)
          else reject(err)
        })
      }
    })
  }

}

mongoose.model('User', userSchema)
