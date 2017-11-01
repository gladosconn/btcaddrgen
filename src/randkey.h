#ifndef __RAND_KEY_H__
#define __RAND_KEY_H__

namespace rnd {

/**
 * Build randomized buffer
 *
 * @param out Allocated buffer to save output buffer.
 * @param num Size of the buffer, must <= 32.
 *
 * @return none
 */
void GetStrongRandBytes(unsigned char *out, int num);

/**
 * Build randomized buffer
 *
 * @param out Allocated buffer to save output buffer.
 * @param num Size of the buffer, must <= 32.
 *
 * @return none
 */
void GetRandBytes(unsigned char *buf, int num);

} // namespace rnd

#endif
