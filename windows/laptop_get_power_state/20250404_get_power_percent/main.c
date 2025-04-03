#include <windows.h>
#include <stdio.h>

int main() {
    SYSTEM_POWER_STATUS powerStatus;
    if (GetSystemPowerStatus(&powerStatus)) {
        if (powerStatus.BatteryFlag == 128) {
            printf("û�м�⵽��ء�\n");
        } else {
            printf("���ʣ�����: %d%%\n", powerStatus.BatteryLifePercent);
            if (powerStatus.BatteryFlag & 8) { // ����Ƿ��ڳ��
                printf("������ڳ�硣\n");
            } else {
                printf("���δ�ڳ�硣\n");
            }
        }
    } else {
        printf("�޷���ȡ��Դ״̬��\n");
    }
    return 0;
}