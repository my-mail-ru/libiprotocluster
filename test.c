#include "iprotocluster.h"

#include <stdlib.h>

#define COUNT 1000
#define CHUNK 100

int main(int argc, char *argv[]) {
    iproto_t *iproto = iproto_init();
    iproto_shard_t *shard = iproto_shard_init();
    iproto_server_t *server = iproto_server_init("188.93.61.208", 30000);
    iproto_shard_add_servers(shard, false, &server, 1);
    iproto_server_free(server);
    iproto_add_shard(iproto, shard);

    char data[] = "\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x8a\xf7\x9a\x3b";
    for (int i = 0; i < COUNT; i++) {
        iproto_message_t *messages[CHUNK];
        for (int j = 0; j < CHUNK; j++)
            messages[j] = iproto_message_init(22, data, sizeof(data));
        iproto_bulk(iproto, messages, CHUNK, NULL);
        for (int j = 0; j < CHUNK; j++)
            iproto_message_free(messages[j]);
    }

    iproto_free(iproto);
}
