#if !defined(AD_VPN_H)
#define AD_VPN_H

#include "../modules/ad_logger/include/ad_logger.h"
#include "../modules/ad_tun/include/ad_tun.h"
#include "../modules/ad_transport/include/ad_transport.h"
#include "../modules/ad_auth/include/ad_auth.h"
#include "../modules/ad_kex/include/ad_kex.h"
#include "../modules/ad_crypt/include/ad_crypt.h"
#include "../modules/ad_routing/include/ad_routing.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief VPN configuration structure
 */
typedef struct {
    const char *config_path;        /**< Path to VPN config file */
    const char *logger_config_path; /**< Path to logger config file */
} ad_vpn_config_t;

/**
 * @brief VPN state
 */
typedef enum {
    AD_VPN_STATE_STOPPED = 0,
    AD_VPN_STATE_INITIALIZING,
    AD_VPN_STATE_RUNNING,
    AD_VPN_STATE_STOPPING,
    AD_VPN_STATE_ERROR
} ad_vpn_state_t;

/**
 * @brief Initialize VPN with configuration
 *
 * @param config VPN configuration
 * @return 0 on success, negative on error
 */
int ad_vpn_init(const ad_vpn_config_t *config);

/**
 * @brief Start VPN service
 *
 * @return 0 on success, negative on error
 */
int ad_vpn_start(void);

/**
 * @brief Stop VPN service
 *
 * @return 0 on success, negative on error
 */
int ad_vpn_stop(void);

/**
 * @brief Cleanup VPN resources
 *
 * @return 0 on success
 */
int ad_vpn_cleanup(void);

/**
 * @brief Get current VPN state
 *
 * @return Current state
 */
ad_vpn_state_t ad_vpn_get_state(void);

#ifdef __cplusplus
}
#endif

#endif // AD_VPN_H