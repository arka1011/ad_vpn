#include "../include/ad_vpn.h"

int main(int argc, char **argv) {

    ad_logger_init("../config/ad_logger.conf");

    ad_tun_config_t config;
    ad_tun_error_t err = ad_tun_load_config("../config/ad_tun.conf", &config);
    ad_tun_init(&config);

    ad_transport_config_t transport_cfg = {
        .config_path = "../config/ad_transport.conf",
        .db_path = "../data/peers.db",
        .persist_interval_sec = 300
    };
    ad_transport_init_with_config(&transport_cfg);

    ad_transport_start();

    ad_transport_stop();
    ad_tun_cleanup();
    ad_logger_fini();
    return 0;
}