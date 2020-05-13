/*
 * HelloJNI.c
 *
 *  Created on: Apr 23, 2020
 *      Author: anhpt0135
 */
#include <jni.h>
#include <stdio.h>
#include "sslBT_SSLClientBT.h"
#include <string.h>
#include <unistd.h>
#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#include "mbedtls/x509.h"
#include <sys/socket.h>
#define DFL_PSK_IDENTITY        "Client_identity"
char sDFLPSK[32] = { 0x63, 0x61, 0x66, 0x65, 0x64, 0x61, 0x30,
		0x65, 0x00 };

static mbedtls_ssl_config g_conf;

static void init_psk(unsigned char *input_psk, unsigned char *psk, int *psk_len) {
	if (strlen(input_psk)) {
		unsigned char c;
		size_t j;

		if (strlen(input_psk) % 2 != 0) {
			printf("*** pre-shared key not valid hex (1)\n");
			return;
		}

		*psk_len = strlen(input_psk) / 2;

		for (j = 0; j < strlen(input_psk); j += 2) {
			c = input_psk[j];
			if (c >= '0' && c <= '9')
				c -= '0';
			else if (c >= 'a' && c <= 'f')
				c -= 'a' - 10;
			else if (c >= 'A' && c <= 'F')
				c -= 'A' - 10;
			else {
				printf("*** pre-shared key not valid hex (2)\n");
				return;
			}
			psk[j / 2] = c << 4;

			c = input_psk[j + 1];
			if (c >= '0' && c <= '9')
				c -= '0';
			else if (c >= 'a' && c <= 'f')
				c -= 'a' - 10;
			else if (c >= 'A' && c <= 'F')
				c -= 'A' - 10;
			else {
				printf("pre-shared key not valid hex (3)\n");
				return;
			}
			psk[j / 2] |= c;
		}
		int y = 0;
		for (y = 0; y < sizeof(psk); y++) {
			printf("*** PSK %02x\n", psk[y]);
		}
	} else
		printf("input_psk is null\n");
}

static struct timeval validTimeout(int timeout) {
	struct timeval t = {timeout/1000, (timeout % 1000) * 1000};
	if (t.tv_sec < 0 || (t.tv_sec == 0 && t.tv_usec <= 0)) {
		t.tv_sec = 0;
		t.tv_usec = 100;
	}
	return t;
}

static int sendfunc(mbedtls_ssl_context *ssl, mbedtls_net_context server, char *buf, int len, int timeout){
	struct timeval t;
	int ret;
	t = validTimeout(timeout);
	setsockopt(server.fd, SOL_SOCKET, SO_SNDTIMEO,(char *) &t, sizeof(struct timeval));
	ret = mbedtls_ssl_write(ssl, (const unsigned char *)buf, len);
	return ret;
}

static int sendSecuredCommand(const char *ip_Addr, const char *portStr, const char *pskStr,
		const char *pskIdentityStr, const char *command, char *response, int timeout) {
	printf("Inside send command function\n");
	const char *pers = "ssl_client";
	char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
	unsigned char psk[MBEDTLS_PSK_MAX_LEN];
	int psk_len = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	int ret = 0;
	char fullCommand[500];
	snprintf(fullCommand, sizeof(fullCommand), "%s%s", "action=command&command=", command);// "action=command&command=get_udid";
	mbedtls_net_context server_ctx;
	mbedtls_net_init(&server_ctx);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&g_conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_init(&entropy);
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			(const unsigned char*) pers, strlen(pers));
	if (ret != 0) {
		printf("mbedtls_ctr_drbg_seed failed\n");
		return -1;
	}

	if ((ret = mbedtls_net_connect(&server_ctx, ip_Addr, portStr,
	MBEDTLS_NET_PROTO_TCP)) != 0) {
		printf("mbedtls_net_connect() failed\n");
		return -1;
	}

	printf("Connected....\n");

	if (mbedtls_ssl_config_defaults(&g_conf,
	MBEDTLS_SSL_IS_CLIENT,
	MBEDTLS_SSL_TRANSPORT_STREAM,
	MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		printf("mbedtls_ssl_config_default() failed\n");
		return -1;
	}

	mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_read_timeout(&g_conf, 5000);

	if(!strlen(pskStr) && !strlen(pskIdentityStr)){
		printf("pskStr NULL\n");
		init_psk((unsigned char*) sDFLPSK, psk, &psk_len);
		if (mbedtls_ssl_conf_psk(&g_conf, psk, psk_len,
				(unsigned char *) DFL_PSK_IDENTITY, strlen(DFL_PSK_IDENTITY)) != 0) {
			printf("mbedtls_ssl_conf_psk() failed\n");
			return -1;
		}
	}
	else {
		init_psk((unsigned char*) pskStr, psk, &psk_len);
		if (mbedtls_ssl_conf_psk(&g_conf, psk, psk_len,
				(unsigned char *) pskIdentityStr, strlen(pskIdentityStr)) != 0) {
			printf("mbedtls_ssl_conf_psk() failed\n");
			return -1;
		}
	}

	printf("mbedtls_ssl_setup()\n");
	if ((ret = mbedtls_ssl_setup(&ssl, &g_conf)) != 0) {
		printf("mbedtls_ssl_setup() failed ret = %d\n", ret);
		return -1;
	}

	mbedtls_ssl_set_bio(&ssl, &server_ctx, mbedtls_net_send, mbedtls_net_recv,
	NULL);

	if ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		printf("Failed : mbedtls_ssl_handshake return -0x%x\n", -ret);
		return -1;
	}

	snprintf((char *) buf, sizeof(buf) - 1, "%s\r\n", fullCommand);

	if((ret = sendfunc(&ssl, server_ctx, buf, strlen(buf), timeout)) < 0){
		printf("Failed: sendfunc failed \n");
		return -1;
	}

	memset(buf, 0, sizeof(buf));

	if((ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf))) < 0){
		printf("mbedtls_ssl_read() failed \n");
		return -1;
	}

	printf("received message: %s\n", buf);
	strncpy(response, buf, strlen(buf) + 1);

	printf("\nClosing socket...\n");

	mbedtls_net_free(&server_ctx);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&g_conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	printf("Finished.\n");
	return 0;
}

JNIEXPORT jstring JNICALL Java_sslBT_SSLClientBT_sendSecuredCommandBT(JNIEnv *env,
		jobject obj, jstring jipAddr, jstring jport, jstring jpsk,
		jstring jpskIdentity, jstring jcommand, jint jtimeout) {
	printf("Hello from HelloJNI.c\n");
	const char *ip_Addr = (*env)->GetStringUTFChars(env, jipAddr, NULL);
	const char *portStr = (*env)->GetStringUTFChars(env, jport, NULL);
	const char *pskStr = (*env)->GetStringUTFChars(env, jpsk, NULL);
	const char *pskIdentityStr = (*env)->GetStringUTFChars(env, jpskIdentity, NULL);
	const char *command = (*env)->GetStringUTFChars(env, jcommand, NULL);
	int timeout = (int) jtimeout;
	printf("%s %s %s %s %s\n", ip_Addr, portStr, pskStr, pskIdentityStr, command);
	char response[256];
	sendSecuredCommand(ip_Addr, portStr, pskStr, pskIdentityStr, command, response, timeout);
	return (*env)->NewStringUTF(env, response);
}
