#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
#include "../include/ad_vpn.h"
}

class AdVpnTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test directory
        test_dir = "/tmp/ad_vpn_test_XXXXXX";
        char *dir = strdup(test_dir.c_str());
        if (mkdtemp(dir) == NULL) {
            FAIL() << "Failed to create test directory";
        }
        test_dir = dir;
        free(dir);

        // Create test config files
        create_test_config();
    }

    void TearDown() override {
        // Cleanup test directory
        if (!test_dir.empty()) {
            std::string cmd = "rm -rf " + test_dir;
            system(cmd.c_str());
        }
    }

    void create_test_config() {
        std::string config_path = test_dir + "/ad_vpn_config.ini";
        std::ofstream config(config_path);
        config << "[ad_tun]\n";
        config << "ifname = ad_test_tun0\n";
        config << "ipv4 = 10.10.0.1/24\n";
        config << "mtu = 1500\n";
        config << "persist = 0\n";
        config << "\n";
        config << "[peer_table]\n";
        config << "capacity = 16\n";
        config << "persist_interval = 10\n";
        config << "db_path = " << test_dir << "/peer_table.db\n";
        config << "\n";
        config << "[peer:test-peer-1]\n";
        config << "real_addr = 127.0.0.1:5000\n";
        config << "routes = 10.8.0.0/24\n";
        config << "active = 1\n";
        config.close();

        std::string logger_config_path = test_dir + "/ad_zlog_config.conf";
        std::ofstream logger_config(logger_config_path);
        logger_config << "[formats]\n";
        logger_config << "simple = \"%d(%F %T) %-6V [%p:%F:%L] %m%n\"\n";
        logger_config << "\n";
        logger_config << "[rules]\n";
        logger_config << "*.INFO \"%V %d(%F %T) %m%n\"\n";
        logger_config.close();
    }

    std::string test_dir;
};

// Test VPN initialization
TEST_F(AdVpnTest, InitSuccess) {
    ad_vpn_config_t config = {
        .config_path = (test_dir + "/ad_vpn_config.ini").c_str(),
        .logger_config_path = (test_dir + "/ad_zlog_config.conf").c_str()
    };

    int ret = ad_vpn_init(&config);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(AD_VPN_STATE_STOPPED, ad_vpn_get_state());

    ad_vpn_cleanup();
}

// Test VPN initialization with NULL config
TEST_F(AdVpnTest, InitNullConfig) {
    int ret = ad_vpn_init(NULL);
    EXPECT_NE(0, ret);
}

// Test VPN initialization with invalid config path
TEST_F(AdVpnTest, InitInvalidConfig) {
    ad_vpn_config_t config = {
        .config_path = "/nonexistent/path/config.ini",
        .logger_config_path = NULL
    };

    int ret = ad_vpn_init(&config);
    EXPECT_NE(0, ret);
}

// Test VPN state transitions
TEST_F(AdVpnTest, StateTransitions) {
    ad_vpn_config_t config = {
        .config_path = (test_dir + "/ad_vpn_config.ini").c_str(),
        .logger_config_path = (test_dir + "/ad_zlog_config.conf").c_str()
    };

    // Initial state should be STOPPED
    EXPECT_EQ(AD_VPN_STATE_STOPPED, ad_vpn_get_state());

    // After init, should be STOPPED
    int ret = ad_vpn_init(&config);
    ASSERT_EQ(0, ret);
    EXPECT_EQ(AD_VPN_STATE_STOPPED, ad_vpn_get_state());

    // Cleanup
    ad_vpn_cleanup();
    EXPECT_EQ(AD_VPN_STATE_STOPPED, ad_vpn_get_state());
}

// Test double initialization
TEST_F(AdVpnTest, DoubleInit) {
    ad_vpn_config_t config = {
        .config_path = (test_dir + "/ad_vpn_config.ini").c_str(),
        .logger_config_path = (test_dir + "/ad_zlog_config.conf").c_str()
    };

    int ret1 = ad_vpn_init(&config);
    EXPECT_EQ(0, ret1);

    // Second init should fail
    int ret2 = ad_vpn_init(&config);
    EXPECT_NE(0, ret2);

    ad_vpn_cleanup();
}

// Test cleanup without init
TEST_F(AdVpnTest, CleanupWithoutInit) {
    // Should not crash
    int ret = ad_vpn_cleanup();
    EXPECT_EQ(0, ret);
}

// Test stop without start
TEST_F(AdVpnTest, StopWithoutStart) {
    ad_vpn_config_t config = {
        .config_path = (test_dir + "/ad_vpn_config.ini").c_str(),
        .logger_config_path = (test_dir + "/ad_zlog_config.conf").c_str()
    };

    int ret = ad_vpn_init(&config);
    ASSERT_EQ(0, ret);

    // Stop should succeed even if not started
    ret = ad_vpn_stop();
    EXPECT_EQ(0, ret);

    ad_vpn_cleanup();
}

// Test multiple cleanup calls
TEST_F(AdVpnTest, MultipleCleanup) {
    ad_vpn_config_t config = {
        .config_path = (test_dir + "/ad_vpn_config.ini").c_str(),
        .logger_config_path = (test_dir + "/ad_zlog_config.conf").c_str()
    };

    int ret = ad_vpn_init(&config);
    ASSERT_EQ(0, ret);

    // Multiple cleanups should not crash
    ad_vpn_cleanup();
    ad_vpn_cleanup();
    ad_vpn_cleanup();
}

// Test with environment variables (if supported)
TEST_F(AdVpnTest, EnvironmentConfig) {
    // Set environment variables
    setenv("AD_VPN_CONFIG", (test_dir + "/ad_vpn_config.ini").c_str(), 1);
    setenv("AD_VPN_LOGGER_CONFIG", (test_dir + "/ad_zlog_config.conf").c_str(), 1);

    // Note: This test verifies the environment variable handling
    // The actual usage would be in main(), but we can test that
    // the config structure accepts the paths
    ad_vpn_config_t config = {
        .config_path = getenv("AD_VPN_CONFIG"),
        .logger_config_path = getenv("AD_VPN_LOGGER_CONFIG")
    };

    if (config.config_path && config.logger_config_path) {
        int ret = ad_vpn_init(&config);
        EXPECT_EQ(0, ret);
        ad_vpn_cleanup();
    }

    unsetenv("AD_VPN_CONFIG");
    unsetenv("AD_VPN_LOGGER_CONFIG");
}

