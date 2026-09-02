#include "deca_version.h"
#ifdef DW3000_DRIVER_VERSION // == 0x040000
#include "deca_device_api.h"
#else
#include "deca_interface.h"
#endif

decaIrqStatus_t decamutexon(void)
{
	return 0;
}

void decamutexoff(decaIrqStatus_t s)
{
}

void deca_sleep(unsigned int time_ms)
{
}

void deca_usleep(unsigned long time_us)
{
}
