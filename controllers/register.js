
module.exports = async (ctx, next) => {
  ctx.body = '我是controllers的register页面'
  // eslint-disable-next-line standard/object-curly-even-spacing
  const { username, password} = ctx.request.body
  const user = require('../database/schemas/user')

  if (username && password) {
    const findname = await user.findOne({username: username})
    if (findname.length) {
      ctx.state = {
        code: 1,
        data: {

          msg: '用户名已注册'
        }
      }
      return
    }

    try {
      await user.findOne({username, password})
      ctx.state.data = {
        msg: 'success'
      }
    } catch (e) {
      ctx.state = {
        code: -1,
        data: {
          msg: '注册失败：' + e.sqlMessage
        }
      }
    }
  }
}
