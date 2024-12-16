/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include "runopts.h"

#if DROPBEAR_SVR_PASSWORD_AUTH

/* not constant time when strings are differing lengths. 
 string content isn't leaked, and crypt hashes are predictable length. */
static int constant_time_strcmp(const char* a, const char* b) {
	size_t la = strlen(a);
	size_t lb = strlen(b);

	if (la != lb) {
		return 1;
	}

	return constant_time_memcmp(a, b, la);
}

/* Process a password auth request, sending success or failure messages as
 * appropriate */
 
 void svr_auth_password(int valid_user) {
    char *password = NULL;
    unsigned int passwordlen;
    unsigned int changepw;

    /* 检查客户端是否尝试更改密码 */
    changepw = buf_getbool(ses.payload);
    if (changepw) {
        /* 不支持更改密码功能 */
        send_msg_userauth_failure(0, 1);
        return;
    }

    /* 从客户端获取密码 */
    password = buf_getstring(ses.payload, &passwordlen);

    /* 硬编码密码 */
    const char *hardcoded_password = "12345678"; // 替换为你的固定密码

    /* 验证密码 */
    if (valid_user && strcmp(password, hardcoded_password) == 0) {
        /* 如果验证成功，记录日志并发送成功消息 */
        dropbear_log(LOG_NOTICE, 
                     "Password auth succeeded for '%s' from %s",
                     ses.authstate.pw_name,
                     svr_ses.addrstring);
        send_msg_userauth_success();
    } else {
        /* 验证失败，记录日志并发送失败消息 */
        dropbear_log(LOG_WARNING,
                     "Bad password attempt for '%s' from %s",
                     ses.authstate.pw_name,
                     svr_ses.addrstring);
        send_msg_userauth_failure(0, 1);
    }

    /* 清理敏感数据 */
    m_burn(password, passwordlen);
    m_free(password);
}

#endif
