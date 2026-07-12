/**
 * Estrategia para auditar la inscripción de dispositivos corporativos (Apple ABM/DEP).
 * ID-146: Administrar dispositivos usando Apple Business Manager (Integración ABM/DEP).
 * Utiliza Cloud Identity Devices API vía Token DWD para listar los dispositivos y evaluar
 * el atributo 'ownerType' en la raíz de cada objeto.
 */
class AppleDeviceEnrollmentStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-146", 
        valueKey: "valorPrincipal",
        noteKey: "comentario146",
        riskKey: "riesgo146",
        scoreKey: "score146"
      }
    ];
    super("Apple DEP/ABM Enrollment Audit (ID-146)", configIDs);
    this.customerId = customerId;
    this.category = "Gestión de dispositivos";
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  evaluateInMemory(globalContext) {
    const { auth } = globalContext;
    if (!auth) {
      return this._buildErrorResponse("Falta el contexto global (objeto auth no encontrado).");
    }

    Logger.log("========== INICIO DIAGNÓSTICO ID-146 (APPLE ABM / OWNER TYPE) ==========");

    let companyOwnedCount = 0;
    let byodCount = 0;
    let unspecifiedCount = 0;
    let totalDevices = 0;

    try {
      // 1. Generar token DWD con el scope de Cloud Identity Devices
      const adminEmail = auth.getCurrentUserEmail();
      const dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/cloud-identity.devices.readonly"
      ]);

      // 2. Extraer dispositivos con paginación
      let pageToken = "";
      let pagesProcessed = 0;

      do {
        let url = `https://cloudidentity.googleapis.com/v1/devices?customer=customers/${this.customerId}&pageSize=100`;
        if (pageToken) url += `&pageToken=${pageToken}`;

        const response = UrlFetchApp.fetch(url, {
          method: "get",
          headers: dwdHeader,
          muteHttpExceptions: true
        });

        if (response.getResponseCode() === 200) {
          const json = JSON.parse(response.getContentText());
          const devices = json.devices || [];
          totalDevices += devices.length;

          // LOG EXPLICATIVO PARA ENTENDER QUÉ TRAE LA API (Muestra el primer dispositivo si existe)
          if (pagesProcessed === 0 && devices.length > 0) {
             Logger.log(`[ID-146 RAW LOG] Ejemplo de dispositivo recibido: ${JSON.stringify(devices[0]).substring(0, 300)}...`);
          }

          devices.forEach(d => {
            const ownerType = d.ownerType || "UNSPECIFIED";
            if (ownerType === "COMPANY_OWNED") {
              companyOwnedCount++;
            } else if (ownerType === "BYOD") {
              byodCount++;
            } else {
              unspecifiedCount++;
            }
          });

          pageToken = json.nextPageToken;
        } else {
          Logger.log(`[ID-146] Error al consultar Devices API: HTTP ${response.getResponseCode()} - ${response.getContentText()}`);
          break;
        }
        
        pagesProcessed++;
        // Límite de seguridad para no agotar cuota (máximo 5 páginas = 500 dispositivos)
        if (pagesProcessed >= 5) {
          Logger.log("[ID-146] Límite de seguridad de 5 páginas alcanzado. Deteniendo extracción.");
          break;
        }

      } while (pageToken);

    } catch (e) {
      Logger.log(`[ID-146] Excepción capturada: ${e.message}`);
      return this._buildErrorResponse(`Error de red o permisos DWD: ${e.message}`);
    }

    Logger.log(`[ID-146] Totales evaluados: ${totalDevices} | Corporativos: ${companyOwnedCount} | BYOD: ${byodCount} | No Especificado: ${unspecifiedCount}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-146 ==========");

    // =====================================================================
    // LÓGICA DE SALIDA Y RIESGO
    // =====================================================================
    let riesgo146 = "Bajo";
    let comentario146 = "";
    let valorPrincipal = "";

    if (totalDevices === 0) {
      riesgo146 = "Medio"; 
      valorPrincipal = "No evaluable (0)";
      comentario146 = "No se encontraron dispositivos registrados en Cloud Identity. No es posible verificar la integración con Apple Business Manager (ABM) o Device Enrollment Program (DEP).";
    } else {
      valorPrincipal = `Corp: ${companyOwnedCount} | BYOD: ${byodCount}`;
      
      if (companyOwnedCount > 0) {
        // Existen dispositivos propiedad de la empresa (COMPANY_OWNED), lo que implica sincronización de inventario.
        riesgo146 = "Bajo";
        comentario146 = `Excelente postura. Se identificaron ${companyOwnedCount} dispositivos marcados con propiedad corporativa (COMPANY_OWNED). Esto confirma que existe una sincronización de inventario activa (ej. a través de ABM/DEP o Zero-Touch) forzando controles de MDM institucionales.`;
      } else {
        // Todo es BYOD o no especificado.
        riesgo146 = "Medio";
        comentario146 = `ATENCIÓN: Se analizaron ${totalDevices} dispositivos, pero ninguno posee el atributo 'COMPANY_OWNED' (inventario corporativo irrenunciable). Actualmente el entorno depende únicamente de inscripciones BYOD (${byodCount}) o no especificadas (${unspecifiedCount}), reduciendo la obligatoriedad del MDM ante borrados de fábrica.`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario146: comentario146,
      riesgo146: riesgo146,
      score146: this.calcularScoreDeRiesgo(riesgo146)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-146] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      riesgo146: "Medio",
      score146: 2,
      comentario146: msg
    };
  }
}