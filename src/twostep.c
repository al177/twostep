#include "pebble_os.h"
#include "pebble_app.h"
#include "pebble_fonts.h"

/********CONFIGURE THIS********/

// Your shared key, BASE64 
// sample key is base32 "JBSWY3DPEHPK3PXP"
const unsigned char sha1_key[] = {
	'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF
};
// size of the above key in bytes
#define SECRET_SIZE 10	
// current time zone offset 
#define TIME_ZONE_OFFSET -5

/******************************/


// Truncate n decimal digits to 2^n for 6 digits
#define DIGITS_TRUNCATE 1000000

#define SHA1_SIZE 20

#define MY_UUID { 0xA4, 0xA6, 0x13, 0xB5, 0x8A, 0x6B, 0x4F, 0xF0, 0xBD, 0x80, 0x00, 0x38, 0xA1, 0x51, 0xCD, 0x86 }
PBL_APP_INFO(MY_UUID,
		"Two Step Token", "pokey9000",
		1, 0, /* App version */
		DEFAULT_MENU_ICON,
		APP_INFO_STANDARD_APP);

Window window;

TextLayer tokenLayer;

/* from sha1.c from liboauth */

/* This code is public-domain - it is based on libcrypt 
 * placed in the public domain by Wei Dai and other contributors.
 */

//#include <stdint.h>
#include <string.h>

/* header */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

union _buffer {
	uint8_t b[BLOCK_LENGTH];
	uint32_t w[BLOCK_LENGTH/4];
};

union _state {
	uint8_t b[HASH_LENGTH];
	uint32_t w[HASH_LENGTH/4];
};

typedef struct sha1nfo {
	union _buffer buffer;
	uint8_t bufferOffset;
	union _state state;
	uint32_t byteCount;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

/* public API - prototypes - TODO: doxygen*/

/*
void sha1_init(sha1nfo *s);
void sha1_writebyte(sha1nfo *s, uint8_t data);
void sha1_write(sha1nfo *s, const char *data, size_t len);
uint8_t* sha1_result(sha1nfo *s);
void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength);
uint8_t* sha1_resultHmac(sha1nfo *s);
*/

/* code */
#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

const uint8_t sha1InitState[] = {
	0x01,0x23,0x45,0x67, // H0
	0x89,0xab,0xcd,0xef, // H1
	0xfe,0xdc,0xba,0x98, // H2
	0x76,0x54,0x32,0x10, // H3
	0xf0,0xe1,0xd2,0xc3  // H4
};

void sha1_init(sha1nfo *s) {
	memcpy(s->state.b,sha1InitState,HASH_LENGTH);
	s->byteCount = 0;
	s->bufferOffset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
	return ((number << bits) | (number >> (32-bits)));
}

void sha1_hashBlock(sha1nfo *s) {
	uint8_t i;
	uint32_t a,b,c,d,e,t;

	a=s->state.w[0];
	b=s->state.w[1];
	c=s->state.w[2];
	d=s->state.w[3];
	e=s->state.w[4];
	for (i=0; i<80; i++) {
		if (i>=16) {
			t = s->buffer.w[(i+13)&15] ^ s->buffer.w[(i+8)&15] ^ s->buffer.w[(i+2)&15] ^ s->buffer.w[i&15];
			s->buffer.w[i&15] = sha1_rol32(t,1);
		}
		if (i<20) {
			t = (d ^ (b & (c ^ d))) + SHA1_K0;
		} else if (i<40) {
			t = (b ^ c ^ d) + SHA1_K20;
		} else if (i<60) {
			t = ((b & c) | (d & (b | c))) + SHA1_K40;
		} else {
			t = (b ^ c ^ d) + SHA1_K60;
		}
		t+=sha1_rol32(a,5) + e + s->buffer.w[i&15];
		e=d;
		d=c;
		c=sha1_rol32(b,30);
		b=a;
		a=t;
	}
	s->state.w[0] += a;
	s->state.w[1] += b;
	s->state.w[2] += c;
	s->state.w[3] += d;
	s->state.w[4] += e;
}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {
	s->buffer.b[s->bufferOffset ^ 3] = data;
	s->bufferOffset++;
	if (s->bufferOffset == BLOCK_LENGTH) {
		sha1_hashBlock(s);
		s->bufferOffset = 0;
	}
}

void sha1_writebyte(sha1nfo *s, uint8_t data) {
	++s->byteCount;
	sha1_addUncounted(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len) {
	for (;len--;) sha1_writebyte(s, (uint8_t) *data++);
}

void sha1_pad(sha1nfo *s) {
	// Implement SHA-1 padding (fips180-2 §5.1.1)

	// Pad with 0x80 followed by 0x00 until the end of the block
	sha1_addUncounted(s, 0x80);
	while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

	// Append length in the last 8 bytes
	sha1_addUncounted(s, 0); // We're only using 32 bit lengths
	sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
	sha1_addUncounted(s, 0); // So zero pad the top bits
	sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
	sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
	sha1_addUncounted(s, s->byteCount >> 13); // byte.
	sha1_addUncounted(s, s->byteCount >> 5);
	sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t* sha1_result(sha1nfo *s) {
	int i;
	// Pad to complete the last block
	sha1_pad(s);

	// Swap byte order back
	for (i=0; i<5; i++) {
		uint32_t a,b;
		a=s->state.w[i];
		b=a<<24;
		b|=(a<<8) & 0x00ff0000;
		b|=(a>>8) & 0x0000ff00;
		b|=a>>24;
		s->state.w[i]=b;
	}

	// Return pointer to hash (20 characters)
	return s->state.b;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength) {
	uint8_t i;
	memset(s->keyBuffer, 0, BLOCK_LENGTH);
	if (keyLength > BLOCK_LENGTH) {
		// Hash long keys
		sha1_init(s);
		for (;keyLength--;) sha1_writebyte(s, *key++);
		memcpy(s->keyBuffer, sha1_result(s), HASH_LENGTH);
	} else {
		// Block length keys are used as is
		memcpy(s->keyBuffer, key, keyLength);
	}
	// Start inner hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) {
		sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_IPAD);
	}
}

uint8_t* sha1_resultHmac(sha1nfo *s) {
	uint8_t i;
	// Complete inner hash
	memcpy(s->innerHash,sha1_result(s),HASH_LENGTH);
	// Calculate outer hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_OPAD);
	for (i=0; i<HASH_LENGTH; i++) sha1_writebyte(s, s->innerHash[i]);
	return sha1_result(s);
}


/* end sha1.c */



void handle_second_tick(AppContextRef ctx, PebbleTickEvent *t) {

	(void)t;
	(void)ctx;

	static char tokenText[] = "RYRYRYRYRY"; // Needs to be static because it's used by the system later.

	PblTm current_time;
	sha1nfo s;
	uint8_t ofs;
	uint32_t otp;
	int i;
	char sha1_time[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	uint32_t unix_time;
	get_time(&current_time);
	
// shamelessly stolen from WhyIsThisOpen's Unix Time source: http://forums.getpebble.com/discussion/4324/watch-face-unix-time
	/* Convert time to seconds since epoch. */
	unix_time = ((0-TIME_ZONE_OFFSET)*3600) + /* time zone offset */
		+ current_time.tm_sec /* start with seconds */
		+ current_time.tm_min*60 /* add minutes */
		+ current_time.tm_hour*3600 /* add hours */                                    + current_time.tm_yday*86400 /* add days */
		+ (current_time.tm_year-70)*31536000 /* add years since 1970 */                + ((current_time.tm_year-69)/4)*86400 /* add a day after leap years, starting in 1973 */                                                                       - ((current_time.tm_year-1)/100)*86400 /* remove a leap day every 100 years, starting in 2001 */                                                               + ((current_time.tm_year+299)/400)*86400; /* add a leap day back every 400 years, starting in 2001*/
	unix_time /= 30;
	sha1_time[4] = (unix_time >> 24) & 0xFF;
	sha1_time[5] = (unix_time >> 16) & 0xFF;
	sha1_time[6] = (unix_time >> 8) & 0xFF;
	sha1_time[7] = unix_time & 0xFF;

	sha1_initHmac(&s, sha1_key, SECRET_SIZE);
	sha1_write(&s, sha1_time, 8);
	sha1_resultHmac(&s);
	
	ofs=s.state.b[SHA1_SIZE-1] & 0xf;

	otp = 0;
	otp = ((s.state.b[ofs] & 0x7f) << 24) |
		((s.state.b[ofs + 1] & 0xff) << 16) |
		((s.state.b[ofs + 2] & 0xff) << 8) |
		(s.state.b[ofs + 3] & 0xff);
	otp %= DIGITS_TRUNCATE;
	
	for(i = 0; i < 6; i++) {
		tokenText[5-i] = 0x30 + (otp % 10);
		otp /= 10;
	}
	tokenText[6]=0;

	text_layer_set_text(&tokenLayer, tokenText);

}

void handle_init(AppContextRef ctx) {
	(void)ctx;

	window_init(&window, "tstep");
	window_stack_push(&window, true /* Animated */);
	window_set_background_color(&window, GColorBlack);

	// Init the text layer used to show the time
	// TODO: Wrap this boilerplate in a function?

	text_layer_init(&tokenLayer, GRect(8, 44, 144-8 /* width */, 168-44 /* height */));
	text_layer_set_text_color(&tokenLayer, GColorWhite);
	text_layer_set_background_color(&tokenLayer, GColorClear);
	text_layer_set_font(&tokenLayer, fonts_get_system_font(FONT_KEY_GOTHAM_34_MEDIUM_NUMBERS));

	handle_second_tick(ctx, NULL);

	layer_add_child(&window.layer, &tokenLayer.layer);
}


void pbl_main(void *params) {
	PebbleAppHandlers handlers = {
		.init_handler = &handle_init,
		.tick_info = {
			.tick_handler = &handle_second_tick,
			.tick_units = SECOND_UNIT
		}
	};
	app_event_loop(params, &handlers);
}
