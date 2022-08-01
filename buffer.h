
struct buffer {
	uint8_t *p;
	size_t len;
	size_t size;
};
static inline void buf_init(struct buffer *buf, size_t size);
static inline void buf_free(struct buffer *buf);
static inline void buf_finish(struct buffer *buf);
static inline void buf_clear(struct buffer *buf);
static void buf_resize(struct buffer *buf, size_t len);
static inline void buf_check_add(struct buffer *buf, size_t len);
#define _buf_add_mem(b, d, l)			\
	buf_check_add(b, l);			\
	memcpy(b->p + b->len, d, l);		\
	b->len += l;
static inline void buf_add_mem(struct buffer *buf, const void *data, size_t len);
static inline void buf_add_buf(struct buffer *buf, const struct buffer *bufa);
static inline void buf_add_uint8(struct buffer *buf, uint8_t val);
static inline void buf_add_uint32(struct buffer *buf, uint32_t val);
static inline void buf_add_uint64(struct buffer *buf, uint64_t val);
static inline void buf_add_data(struct buffer *buf, const struct buffer *data);
static inline void buf_add_string(struct buffer *buf, const char *str);
static int buf_check_get(struct buffer *buf, size_t len);
static inline int buf_get_mem(struct buffer *buf, void *data, size_t len);
static inline int buf_get_uint8(struct buffer *buf, uint8_t *val);
static inline int buf_get_uint32(struct buffer *buf, uint32_t *val);
static inline int buf_get_uint64(struct buffer *buf, uint64_t *val);
static inline int buf_get_data(struct buffer *buf, struct buffer *data);
static inline int buf_get_string(struct buffer *buf, char **str);

