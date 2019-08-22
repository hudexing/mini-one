
module.exports = async (ctx) => {
  // eslint-disable-next-line standard/object-curly-even-spacing
  const { username, password} = ctx.request.body

  if (username && password) {
    const findname = await mysql('customers').select().where('username', username)
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
      await mysql('customers').insert({username, password})
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
