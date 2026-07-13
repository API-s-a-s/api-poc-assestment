/**
 * Suite de pruebas para verificar qué APIs de gestión de dispositivos y políticas
 * están disponibles, cuáles responden correctamente, y extraer el 100% DE LOS DISPOSITIVOS.
 */
class DeviceApiTester {
  constructor() {
    this.auth = new AuthService();
    this.customerId = this.auth.getCustomerId();
    this.adminEmail = this.auth.getCurrentUserEmail();
  }

  runAllTests() {
    Logger.log("==========================================================================");
    Logger.log("🧪 INICIANDO PRUEBA DE EXTRACCIÓN TOTAL DE DISPOSITIVOS");
    Logger.log(`Cliente: ${this.customerId} | Administrador: ${this.adminEmail}`);
    Logger.log("==========================================================================");

    // 1. Ejecutar Pruebas de Directory API (MobileDevices) - EXTRACCIÓN TOTAL
    this.testDirectoryApiMobileDevices();

    // 2. Ejecutar Pruebas de Cloud Identity Devices API - EXTRACCIÓN TOTAL
    this.testCloudIdentityDevicesApi();

    // 3. (Opcional) Ejecutar Pruebas de Cloud Identity Policy API
    this.testCloudIdentityPolicyApi();

    Logger.log("==========================================================================");
    Logger.log("🏁 EXTRACCIÓN DE DISPOSITIVOS COMPLETADA");
    Logger.log("==========================================================================");
  }

  /**
   * 1. Directory API (Mobile Devices) - Bucle de paginación
   */
  testDirectoryApiMobileDevices() {
    Logger.log("\n--- [1] EXTRACCIÓN TOTAL: DIRECTORY API (MOBILE DEVICES) ---");

    try {
      const dwdHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly"
      ]);

      let allDirectoryDevices = [];
      let pageToken = "";
      let pageCount = 0;

      do {
        pageCount++;
        let url = `https://admin.googleapis.com/admin/directory/v1/customer/${this.customerId}/devices/mobile?maxResults=100`;
        if (pageToken) url += `&pageToken=${pageToken}`;

        Logger.log(`[TEST] Consultando página ${pageCount} de Directory API...`);
        const response = UrlFetchApp.fetch(url, {
          method: "get",
          headers: dwdHeader,
          muteHttpExceptions: true
        });

        if (response.getResponseCode() === 200) {
          const json = JSON.parse(response.getContentText());
          if (json.mobiledevices) {
            allDirectoryDevices = allDirectoryDevices.concat(json.mobiledevices);
          }
          pageToken = json.nextPageToken;
        } else {
          Logger.log(`[FAILED] Error HTTP ${response.getResponseCode()}: ${response.getContentText()}`);
          break;
        }
      } while (pageToken);

      Logger.log(`[SUCCESS] Extracción total completada. Dispositivos en Directory API: ${allDirectoryDevices.length}`);

      if (allDirectoryDevices.length > 0) {
        allDirectoryDevices.forEach((device, idx) => {
          Logger.log(`\n--- Directory Device [${idx + 1} / ${allDirectoryDevices.length}] ---`);
          Logger.log(JSON.stringify(device, null, 2));
        });
      }

    } catch (e) {
      Logger.log(`[ERROR] Fallo en Directory API: ${e.message}`);
    }
  }

  /**
   * 2. Cloud Identity Devices API - Bucle de paginación para el 100% de los datos
   */
  testCloudIdentityDevicesApi() {
    Logger.log("\n--- [2] EXTRACCIÓN TOTAL: CLOUD IDENTITY DEVICES API ---");

    try {
      const dwdHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/cloud-identity.devices.readonly"
      ]);

      let allCloudIdentityDevices = [];
      let pageToken = "";
      let pageCount = 0;

      // Bucle de paginación para extraer todos los dispositivos
      do {
        pageCount++;
        let url = `https://cloudidentity.googleapis.com/v1/devices?customer=customers/${this.customerId}&pageSize=100`;
        if (pageToken) url += `&pageToken=${pageToken}`;

        Logger.log(`[TEST] Consultando página ${pageCount} de Cloud Identity Devices...`);
        const response = UrlFetchApp.fetch(url, {
          method: "get",
          headers: dwdHeader,
          muteHttpExceptions: true
        });

        if (response.getResponseCode() === 200) {
          const json = JSON.parse(response.getContentText());
          if (json.devices) {
            allCloudIdentityDevices = allCloudIdentityDevices.concat(json.devices);
          }
          pageToken = json.nextPageToken;
        } else {
          Logger.log(`[FAILED] Error HTTP ${response.getResponseCode()}: ${response.getContentText()}`);
          break;
        }
      } while (pageToken);

      Logger.log(`[SUCCESS] Extracción total completada. Dispositivos en Cloud Identity: ${allCloudIdentityDevices.length}`);

      // Imprimir cada dispositivo encontrado con su sub-recurso de usuarios
      allCloudIdentityDevices.forEach((device, index) => {
        Logger.log(`\n==========================================================================`);
        Logger.log(`📱 DISPOSITIVO CLOUD IDENTITY [${index + 1} / ${allCloudIdentityDevices.length}]`);
        Logger.log(`==========================================================================`);
        Logger.log(`[METADATOS DEL DISPOSITIVO]`);
        Logger.log(JSON.stringify(device, null, 2));

        // Buscar el sub-recurso de usuarios para este dispositivo específico
        const deviceName = device.name;
        if (deviceName) {
          const usersUrl = `https://cloudidentity.googleapis.com/v1/${deviceName}/deviceUsers?pageSize=100`;
          const usersResponse = UrlFetchApp.fetch(usersUrl, {
            method: "get",
            headers: dwdHeader,
            muteHttpExceptions: true
          });

          if (usersResponse.getResponseCode() === 200) {
            const usersJson = JSON.parse(usersResponse.getContentText());
            Logger.log(`\n👥 USUARIOS REGISTRADOS EN ESTE DISPOSITIVO (deviceUsers):`);
            Logger.log(JSON.stringify(usersJson.deviceUsers || [], null, 2));
          } else {
            Logger.log(`[FAILED] No se pudo extraer deviceUsers para ${deviceName}`);
          }
        }
      });

    } catch (e) {
      Logger.log(`[ERROR] Fallo en Cloud Identity Devices API: ${e.message}`);
    }
  }

  /**
   * 3. Cloud Identity Policy API
   */
  testCloudIdentityPolicyApi() {
    Logger.log("\n--- [3] PROBANDO CLOUD IDENTITY POLICY API ---");

    const filter = `customer=="customers/${this.customerId}"`;
    const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&pageSize=100`;

    try {
      const privilegedHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
      ]);
      this.executePolicyListCall("Cloud Identity Policy API", url, privilegedHeader);
    } catch (e) {
      Logger.log(`[ERROR] Policy API: ${e.message}`);
    }
  }

  /**
   * Ejecuta la llamada física de lista de políticas y loggea los resultados.
   */
  executePolicyListCall(label, url, headers) {
    try {
      const response = UrlFetchApp.fetch(url, {
        method: "get",
        headers: { ...headers, "Cache-Control": "no-cache" },
        muteHttpExceptions: true
      });

      const code = response.getResponseCode();
      if (code !== 200) return;

      const json = JSON.parse(response.getContentText());
      const policies = json.policies || [];
      Logger.log(`[SUCCESS] ${label} recuperó ${policies.length} políticas.`);
    } catch (e) {
      Logger.log(`[FAILED] ${label} excepción crítica: ${e.message}`);
    }
  }
}