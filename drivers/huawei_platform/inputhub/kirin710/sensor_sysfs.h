#ifndef __SENSOR_SYSFS_H
#define __SENSOR_SYSFS_H

#include "sensor_config.h"

struct pdr_start_config {
	unsigned int report_interval;
	unsigned int report_precise;
	unsigned int report_count;
	unsigned int report_times;
};

struct acc_gyr_offset_threshold {
	int32_t low_threshold;
	int32_t high_threshold;
};

typedef struct {
	unsigned int sub_cmd;
	union {
		struct pdr_start_config start_param;
		unsigned int stop_param;
	};
} pdr_ioctl_t;

typedef enum{
	OFFSET_MIN_THREDHOLD,
	OFFSET_MAX_THREDHOLD,
	DIFF_MIN_THREDHOLD,
	DIFF_MAX_THREDHOLD
}SEMTECK_THREDHOLD;

typedef enum{
	PS_XTALK_CALIBRATE = 0x01,
	PS_5CM_CALIBRATE,// 2
	PS_3CM_CALIBRATE,// 3
	TOF_ZERO_CALIBRATE,// 4
	TOF_6CM_CALIBRATE,// 5
	TOF_10CM_CALIBRATE,// 6
	TOF_60CM_CALIBRATE,// 7
}PS_TOF_CALIBRATE_ORDER;

#define CLI_TIME_STR_LEN (20)
#define CLI_CONTENT_LEN_MAX (256)
#define BL_SETTING_LEN 16
#define SENSOR_LIST_NUM 50
#define DEBUG_DATA_LENGTH 10

#define DATA_CLLCT	"/data/hwzd_logs/dataCollection.log"
#define HAND_DATA_CLLCT	"/data/hwzd_logs/handSensorCalibData.log"

#define ACC_CALI_X_OFFSET	"testName:ACC_CALI_X_OFFSET*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_Y_OFFSET	"testName:ACC_CALI_Y_OFFSET*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_Z_OFFSET	"testName:ACC_CALI_Z_OFFSET*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_X_SEN		"testName:ACC_CALI_X_SEN*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_Y_SEN		"testName:ACC_CALI_Y_SEN*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_Z_SEN		"testName:ACC_CALI_Z_SEN*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_00		"testName:ACC_CALI_XIS_00*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_01		"testName:ACC_CALI_XIS_01*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_02		"testName:ACC_CALI_XIS_02*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_10		"testName:ACC_CALI_XIS_10*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_11		"testName:ACC_CALI_XIS_11*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_12		"testName:ACC_CALI_XIS_12*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_20		"testName:ACC_CALI_XIS_20*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_21		"testName:ACC_CALI_XIS_21*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ACC_CALI_XIS_22		"testName:ACC_CALI_XIS_22*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define PS_CALI_RAW_DATA	"testName:PS_CALI_RAW_DATA*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define ALS_CALI_R		"testName:ALS_CALI_R*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:NA*#errorCode:%s*#time:%s*#\n"
#define ALS_CALI_G		"testName:ALS_CALI_G*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:NA*#errorCode:%s*#time:%s*#\n"
#define ALS_CALI_B		"testName:ALS_CALI_B*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:NA*#errorCode:%s*#time:%s*#\n"
#define ALS_CALI_C		"testName:ALS_CALI_C*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:NA*#errorCode:%s*#time:%s*#\n"
#define ALS_CALI_LUX		"testName:ALS_CALI_LUX*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:NA*#errorCode:%s*#time:%s*#\n"
#define ALS_CALI_CCT		"testName:ALS_CALI_CCT*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:NA*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_X_OFFSET	"testName:GYRO_CALI_X_OFFSET*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_Y_OFFSET	"testName:GYRO_CALI_Y_OFFSET*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_Z_OFFSET	"testName:GYRO_CALI_Z_OFFSET*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_X_SEN	"testName:GYRO_CALI_X_SEN*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_Y_SEN	"testName:GYRO_CALI_Y_SEN*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_Z_SEN	"testName:GYRO_CALI_Z_SEN*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_00	"testName:GYRO_CALI_XIS_00*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_01	"testName:GYRO_CALI_XIS_01*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_02	"testName:GYRO_CALI_XIS_02*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_10	"testName:GYRO_CALI_XIS_10*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_11	"testName:GYRO_CALI_XIS_11*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_12	"testName:GYRO_CALI_XIS_12*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_20	"testName:GYRO_CALI_XIS_20*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_21	"testName:GYRO_CALI_XIS_21*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define GYRO_CALI_XIS_22	"testName:GYRO_CALI_XIS_22*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:%d*#errorCode:%s*#time:%s*#\n"
#define PRESS_CALI_OFFSET	"testName:PRESS_CALI_OFFSET*#value:%d*#minThreshold:NA*#maxThreshold:NA*#result:%s*#cycle:NA*#errorCode:%s*#time:%s*#\n"

#define RGB_SENSOR_CAL_FILE_PATH "/data/light"
#define RGB_SENSOR_CAL_RESULT_MAX_LEN  (96)
#define GYRO_DYN_CALIBRATE_END_ORDER  (5)
extern int read_calibrate_data_from_nv(int nv_number, int nv_size, char *nv_name);
extern int fingersense_commu(unsigned int cmd, unsigned int pare, unsigned int responsed, bool is_subcmd);
extern int fingersense_enable(unsigned int enable);
extern ssize_t sensors_calibrate_show(int tag, struct device *dev, struct device_attribute *attr, char *buf);
extern ssize_t sensors_calibrate_store(int tag, struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
extern ssize_t show_sensor_read_airpress_common(struct device *dev, struct device_attribute *attr, char *buf);
extern int ois_commu(int tag, unsigned int cmd, unsigned int pare, unsigned int responsed, bool is_subcmd);
extern ssize_t show_cap_prox_calibrate_method(struct device *dev, struct device_attribute *attr, char *buf);
extern ssize_t show_cap_prox_calibrate_orders(struct device *dev, struct device_attribute *attr, char *buf);

read_info_t send_airpress_calibrate_cmd(uint8_t tag, unsigned long val, RET_TYPE *rtype);

#endif //__SENSOR_SYSFS_H
