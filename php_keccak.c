#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/basic_functions.h"
#include "ext/hash/php_hash.h"
#include "KeccakNISTInterface.h"
#include "php_keccak.h"

#define KECCAK_DEFAULT_BIT_LENGTH 512

zend_function_entry keccak_functions[] = {
	PHP_FE(keccak_hash, NULL)
	{NULL, NULL, NULL}
};

zend_module_entry keccak_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"keccak",
	keccak_functions,
	PHP_MINIT(keccak),
	PHP_MSHUTDOWN(keccak),
	NULL,
	NULL,
	PHP_MINFO(keccak),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1",
#endif
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_KECCAK
ZEND_GET_MODULE(keccak)
#endif

PHP_MINIT_FUNCTION(keccak)
{
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(keccak)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(keccak)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "keccak hash support", "enabled");
	php_info_print_table_end();
}

PHP_FUNCTION(keccak_hash)
{
#if ZEND_MODULE_API_NO >= 20151012
    zend_long hash_bit_length = KECCAK_DEFAULT_BIT_LENGTH;
    zend_long hash_byte_length;
    size_t buffer_size;
#else
    long hash_bit_length = KECCAK_DEFAULT_BIT_LENGTH;
    long hash_byte_length;
    int buffer_size;
#endif
    BitSequence *buffer = NULL;
    BitSequence hash[64];
    zend_bool raw_output = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &buffer, &buffer_size, &hash_bit_length, &raw_output) == FAILURE)
    {
        RETURN_FALSE;
    }

    memset(hash, 0, sizeof hash);
    HashReturn result;

    if ((result = Hash((size_t) hash_bit_length, buffer, buffer_size * 8, hash)) != HASH_SUCCESS)
    {
        if (result == BAD_HASHLEN)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "Bad bit-length");
        }

        RETURN_FALSE;
    }

    hash_byte_length = ceil(hash_bit_length / 8);

    if (raw_output) {
#if ZEND_MODULE_API_NO >= 20151012
        RETVAL_STRINGL((char *)hash, hash_byte_length);
#else
        RETURN_STRINGL((char *)hash, hash_byte_length, 1);
#endif
    } else {
        char *hexDigest = safe_emalloc(hash_byte_length, 2, 1);

        php_hash_bin2hex(hexDigest, hash, hash_byte_length);
        hexDigest[2 * hash_byte_length] = 0;
#if ZEND_MODULE_API_NO >= 20151012
        RETVAL_STRINGL(hexDigest, hash_byte_length * 2);
#else
        RETURN_STRINGL(hexDigest, hash_byte_length * 2, 1);
#endif
    }
}
