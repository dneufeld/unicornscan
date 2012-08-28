#ifndef _PRNG_H
# define _PRNG_H

#define prng_init genrand_init
#define prng_get32 genrand_get32

void		genrand_init(void);
uint32_t	genrand_get32(void);

#endif
