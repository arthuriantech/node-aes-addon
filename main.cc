#include <cstring>
#include <node.h>
#include <node_buffer.h>
#include "aes256.h"

using std::memcpy;
using v8::FunctionCallbackInfo;
using v8::Exception;
using v8::Isolate;
using v8::MaybeLocal;
using v8::Local;
using v8::NewStringType;
using v8::Object;
using v8::String;
using v8::Value;

// One of two functions from aes256.h:
// aes256_encrypt_ecb
// aes256_decrypt_ecb
typedef void (*aes_function_t)(aes256_context *, uint8_t *);


void AES256Encryption(const FunctionCallbackInfo<Value> &args, aes_function_t aes_function) {
	Isolate *isolate = args.GetIsolate();
	
	if (args.Length() != 2) {
		const char *msg = "Takes exactly 2 arguments";
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, msg)));
		return;
    }
	
	if (!args[0]->IsArrayBufferView()) {
		const char *msg = "Argument 1 (key) must be a Buffer type";
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, msg)));
		return;
    }
	
    if (!args[1]->IsArrayBufferView()) {
		const char *msg = "Argument 2 (data) must be a Buffer type";
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, msg)));
		return;
    }
	
	uint8_t *key = (uint8_t *) node::Buffer::Data(args[0]);
	uint8_t *src = (uint8_t *) node::Buffer::Data(args[1]);
	size_t key_length = node::Buffer::Length(args[0]);
	size_t src_length = node::Buffer::Length(args[1]);
	
	if (key_length > 32) {
		const char *msg = "Length of argument 1 (key) must be <= 32";
		isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, msg)));
		return;
	}
	
	if (src_length % 16) {
		const char *msg = "Length of argument 2 (data) must be multiple of 16";
		isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg)));
		return;
	}

	Local<Object> return_buffer;
	
	if (!node::Buffer::New(isolate, src_length).ToLocal(&return_buffer)) {
		const char *msg = "Buffer creation failed";
		isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg)));
		return;
	}

	uint8_t *dst = (uint8_t *) node::Buffer::Data(return_buffer);
	uint8_t aes_key_block[32] = {0};

	memcpy((void *) aes_key_block, key, key_length);
	
	aes256_context ctx;
	aes256_init(&ctx, aes_key_block);
	
	for (size_t i = 0; (i + 16) <= src_length; i += 16) {
		uint8_t *src_current = src + i;
		uint8_t *dst_current = dst + i;
		
		memcpy((void *) dst_current, src_current, 16);
		aes_function(&ctx, dst_current);
	}
	
	aes256_done(&ctx);
	args.GetReturnValue().Set(return_buffer);
}


void AddonMethod_encrypt(const FunctionCallbackInfo<Value> &args) {
	AES256Encryption(args, aes256_encrypt_ecb);
}


void AddonMethod_decrypt(const FunctionCallbackInfo<Value> &args) {
	AES256Encryption(args, aes256_decrypt_ecb);
}


void Initialize(Local<Object> exports) {
	NODE_SET_METHOD(exports, "encrypt", AddonMethod_encrypt);
	NODE_SET_METHOD(exports, "decrypt", AddonMethod_decrypt);
}


NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)


