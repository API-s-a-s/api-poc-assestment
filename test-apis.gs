/**
 * Suite de pruebas para verificar qué APIs de gestión de dispositivos y políticas
 * están disponibles, cuáles responden correctamente, y cuáles son sus variables exactas
 * (casing, nombres y subestructuras).
 */
class DeviceApiTester {
  constructor() {
    this.auth = new AuthService();
    this.customerId = this.auth.getCustomerId();
    this.adminEmail = this.auth.getCurrentUserEmail();
  }

  runAllTests() {
    Logger.log("==========================================================================");
    Logger.log("🧪 INICIANDO PRUEBA DE APIS DE DISPOSITIVOS Y POLÍTICAS (CSV)");
    Logger.log(`Cliente: ${this.customerId} | Administrador: ${this.adminEmail}`);
    Logger.log("==========================================================================");

    // 1. Ejecutar Pruebas de Directory API (MobileDevices)
    this.testDirectoryApiMobileDevices();

    // 2. Ejecutar Pruebas de Cloud Identity Devices API
    this.testCloudIdentityDevicesApi();

    // 3. Ejecutar Pruebas de Cloud Identity Policy API
    this.testCloudIdentityPolicyApi();

    Logger.log("==========================================================================");
    Logger.log("🏁 PRUEBA DE APIS DE DISPOSITIVOS Y POLÍTICAS COMPLETADA");
    Logger.log("==========================================================================");
  }

  /**
   * 1. Directory API (Mobile Devices)
   * ID-142, ID-143, ID-144, ID-146, ID-153, ID-154
   */
  testDirectoryApiMobileDevices() {
    Logger.log("\n--- [1] PROBANDO DIRECTORY API (MOBILE DEVICES) ---");

    // A. Probar Servicio Avanzado nativo (AdminDirectory)
    try {
      Logger.log("[TEST] Consultando mediante servicio avanzado AdminDirectory...");
      const response = AdminDirectory.Mobiledevices.list(this.customerId, {
        maxResults: 5
      });
      Logger.log(`[SUCCESS] AdminDirectory.Mobiledevices.list respondió. Dispositivos encontrados: ${response.mobiledevices ? response.mobiledevices.length : 0}`);
      if (response.mobiledevices && response.mobiledevices.length > 0) {
        Logger.log("[RAW JSON] Estructura del primer dispositivo en Directory API:");
        Logger.log(JSON.stringify(response.mobiledevices[0], null, 2));
      } else {
        Logger.log("[INFO] No se encontraron dispositivos móviles registrados en el directorio.");
      }
    } catch (e) {
      Logger.log(`[FAILED] AdminDirectory.Mobiledevices.list falló: ${e.message}`);
    }

    // B. Probar llamadas REST directas con diferentes Tokens
    const restUrl = `https://admin.googleapis.com/admin/directory/v1/customer/${this.customerId}/devices/mobile?maxResults=5`;
    
    // B1. Con Token Interactivo Estándar
    this.testFetchEndpoint("Directory API REST (Standard Token)", restUrl, {
      method: "get",
      headers: this.auth.getAuthHeader()
    });

    // B2. Con DWD (admin.directory.device.mobile.readonly)
    try {
      const dwdHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly"
      ]);
      this.testFetchEndpoint("Directory API REST (DWD - Mobile Readonly Scope)", restUrl, {
        method: "get",
        headers: dwdHeader
      });
    } catch (e) {
      Logger.log(`[DWD SETUP ERROR] No se pudo generar token DWD para Directory API: ${e.message}`);
    }

    // B3. Con DWD (admin.directory.device.mobile) — scope read-write que SÍ está en DWD
    try {
      const dwdRwHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/admin.directory.device.mobile"
      ]);
      this.testFetchEndpoint("Directory API REST (DWD - Mobile Read-Write Scope)", restUrl, {
        method: "get",
        headers: dwdRwHeader
      });
    } catch (e) {
      Logger.log(`[DWD SETUP ERROR] No se pudo generar token DWD para Directory API con mobile r/w: ${e.message}`);
    }
  }

  /**
   * 2. Cloud Identity Devices API
   * ID-141, ID-145, ID-150, ID-158
   */
  testCloudIdentityDevicesApi() {
    Logger.log("\n--- [2] PROBANDO CLOUD IDENTITY DEVICES API ---");

    const url = `https://cloudidentity.googleapis.com/v1/devices?customer=customers/${this.customerId}&pageSize=5`;

    // A. Test con Token Estándar
    this.testFetchEndpoint("Cloud Identity Devices API (Standard Token)", url, {
      method: "get",
      headers: this.auth.getAuthHeader()
    }, (json) => {
      const devices = json.devices || [];
      Logger.log(`[INFO] Encontrados ${devices.length} dispositivos en Cloud Identity API.`);
      if (devices.length > 0) {
        Logger.log("[RAW JSON] Estructura del primer dispositivo en Cloud Identity:");
        Logger.log(JSON.stringify(devices[0], null, 2));

        // Probar sub-recurso: deviceUsers si existe
        const deviceName = devices[0].name; // ej. devices/12345
        if (deviceName) {
          const usersUrl = `https://cloudidentity.googleapis.com/v1/${deviceName}/deviceUsers?pageSize=5`;
          this.testFetchEndpoint(`DeviceUsers sub-resource for ${deviceName}`, usersUrl, {
            method: "get",
            headers: this.auth.getAuthHeader()
          });
        }
      }
    });

    // B. Test con DWD (cloud-identity.devices.readonly) — SCOPE AUTORIZADO EN DWD
    try {
      const dwdHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/cloud-identity.devices.readonly"
      ]);
      this.testFetchEndpoint("Cloud Identity Devices API (DWD - cloud-identity.devices.readonly)", url, {
        method: "get",
        headers: dwdHeader
      }, (json) => {
        const devices = json.devices || [];
        Logger.log(`[INFO] DWD Devices Readonly: Encontrados ${devices.length} dispositivos.`);
        if (devices.length > 0) {
          Logger.log("[RAW JSON] Estructura del primer dispositivo (DWD):");
          Logger.log(JSON.stringify(devices[0], null, 2));

          // Probar sub-recurso: deviceUsers
          const deviceName = devices[0].name;
          if (deviceName) {
            const usersUrl = `https://cloudidentity.googleapis.com/v1/${deviceName}/deviceUsers?pageSize=5`;
            this.testFetchEndpoint(`DeviceUsers sub-resource for ${deviceName} (DWD)`, usersUrl, {
              method: "get",
              headers: dwdHeader
            });
          }
        }
      });
    } catch (e) {
      Logger.log(`[DWD SETUP ERROR] No se pudo generar token DWD con cloud-identity.devices.readonly: ${e.message}`);
    }
  }

  /**
   * 3. Cloud Identity Policy API
   * ID-140, ID-147, ID-148, ID-149, ID-151, ID-152, ID-155, ID-156, ID-157
   */
  testCloudIdentityPolicyApi() {
    Logger.log("\n--- [3] PROBANDO CLOUD IDENTITY POLICY API ---");

    const filter = `customer=="customers/${this.customerId}"`;
    const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&pageSize=100`;

    // A. Test con DWD (cloud-identity.policies.readonly)
    try {
      Logger.log("[TEST] Consultando políticas con DWD (cloud-identity.policies.readonly)...");
      const privilegedHeader = this.auth.getPrivilegedAuthHeader(this.adminEmail, [
        "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
      ]);
      this.executePolicyListCall("Cloud Identity Policy API (DWD - Policies Readonly)", url, privilegedHeader);
    } catch (e) {
      Logger.log(`[DWD SETUP ERROR] No se pudo generar token DWD para Policy API con policies.readonly: ${e.message}`);
    }

    // NOTA: El scope cloud-platform NO está autorizado en DWD.
    // Solo cloud-identity.policies.readonly está delegado.
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
      Logger.log(`[STATUS] ${label} -> HTTP ${code}`);
      
      if (code !== 200) {
        Logger.log(`[FAILED] ${label} falló: ${response.getContentText()}`);
        return;
      }

      const json = JSON.parse(response.getContentText());
      const policies = json.policies || [];
      Logger.log(`[SUCCESS] ${label} recuperó ${policies.length} políticas.`);

      // Listar todos los tipos de políticas configurados
      const types = policies.map(p => p.setting ? p.setting.type : "Desconocido");
      const uniqueTypes = [...new Set(types)];
      Logger.log(`[INFO] ${label} -> Tipos únicos: ${uniqueTypes.join(", ")}`);

      // Filtrar y mostrar a detalle las políticas que coincidan con términos del CSV
      const searchTerms = ["device", "password", "sharing", "apps", "workspace_marketplace", "imap", "mobile", "gmail"];
      
      policies.forEach(policy => {
        const type = (policy.setting && policy.setting.type) || "";
        const matchesTerm = searchTerms.some(term => type.toLowerCase().includes(term));

        if (matchesTerm) {
          Logger.log(`\n==========================================================================`);
          Logger.log(`🔍 DETALLE DE POLÍTICA [${label}]: ${type}`);
          Logger.log(`Nombre: ${policy.name}`);
          Logger.log(`Query: ${policy.policyQuery ? JSON.stringify(policy.policyQuery) : "Ninguno"}`);
          Logger.log(`[RAW JSON] Valor y estructura completa:`);
          Logger.log(JSON.stringify(policy, null, 2));
          Logger.log(`==========================================================================`);
        }
      });
    } catch (e) {
      Logger.log(`[FAILED] ${label} excepción crítica: ${e.message}`);
    }
  }

  /**
   * Helper genérico para hacer UrlFetchApp y loggear la respuesta de manera controlada.
   */
  testFetchEndpoint(label, url, options, onSuccessCallback = null) {
    Logger.log(`[TEST] Consultando ${label}...`);
    try {
      options.muteHttpExceptions = true;
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      Logger.log(`[STATUS] ${label} -> HTTP ${code}`);
      
      const text = response.getContentText();
      if (code === 200) {
        try {
          const json = JSON.parse(text);
          Logger.log(`[SUCCESS] ${label} respondió correctamente.`);
          if (onSuccessCallback) {
            onSuccessCallback(json);
          } else {
            // Muestra una porción para no sobrecargar el buffer
            const keys = Object.keys(json);
            Logger.log(`[SUCCESS] Llaves de respuesta: ${keys.join(", ")}`);
            if (keys.length > 0) {
              const snippet = {};
              keys.slice(0, 3).forEach(k => snippet[k] = json[k]);
              Logger.log(`[RAW JSON SNIPPET] ${JSON.stringify(snippet, null, 2)}`);
            }
          }
        } catch (e) {
          Logger.log(`[SUCCESS] ${label} respondió texto plano: ${text.substring(0, 200)}...`);
        }
      } else {
        Logger.log(`[FAILED] ${label} error payload: ${text.substring(0, 300)}...`);
      }
    } catch (e) {
      Logger.log(`[FAILED] ${label} excepción crítica: ${e.message}`);
    }
  }
}
