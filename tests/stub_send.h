/* stub_send.h -- the send_ip_handler() test double (stub_send.c) */
#ifndef HPING_STUB_SEND_H
#define HPING_STUB_SEND_H

#define STUB_MAX_TIMES 64

extern unsigned char stub_last_packet[];
extern unsigned int stub_last_size;
extern unsigned int stub_send_calls;
extern int stub_send_fail;
extern long long stub_send_us[STUB_MAX_TIMES];
extern int stub_send_dport[STUB_MAX_TIMES];

void stub_send_reset(void);
int stub_probes_to(int dport);

#endif
