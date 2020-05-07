# 安全加密算法的中文版

pull-box-stream 的实现不能被直接拿来加密一个 TCP 连接，除非和其他秘钥握手协议配合使用。

如果不握手，最简单的就是用途加密一个文件。

## 声明

### 所有字节都是要经过鉴权和加密的

* 接收者任何时候都不会读到未经鉴权的字节数据。

## 协议

This protocol has no malleable bytes.
Even the framing is authenticated, and since the framing is
authenticated separately to the packet content, an attacker cannot
flip any bits without being immediately detected.
