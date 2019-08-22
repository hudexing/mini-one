module.exports = async (ctx, next) => {
  ctx.body = '你好，我是从controllers.index过来的,admin文件！'
  // res.semd('你好，我是从controllers.index过来的,admin文件！')
  ctx.body = '你好，我是从controllers.index过来的,admin文件！ 对不起，只有管理员才能进入后台管理！'
}


