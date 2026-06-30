/**
 * Estrategia para auditar la edad de las claves de una Cuenta de Servicio en GCP.
 * Evalúa si las claves gestionadas por usuarios tienen más de 90 días.
 */
class ServiceAccountKeyAgeStrategy extends ApiStrategy {
  constructor(projectId, serviceAccountId) { 
    const configIDs = [
      { 
        id: "ID-052", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario052",
        riskKey: "riesgo052",
        scoreKey: "score052"
      }
    ];

    super("GCP Service Account Key Age Audit", configIDs);
    this.url = `https://iam.googleapis.com/v1/projects/${projectId}/serviceAccounts/${serviceAccountId}/keys`;
    this.category = "Integración de aplicaciones";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true,
      headers: {
        "x-goog-user-project": this.url.split("/projects/")[1].split("/")[0]
      }
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  parseResponse(json) {
    if (json.error) {
      const errMsg = json.error.message || JSON.stringify(json.error);
      const errStatus = json.error.status || json.error.code || "UNKNOWN";
      
      let finalMsg = `GCP Error [${errStatus}]: ${errMsg}. `;
      if (errMsg.includes("Permission denied") || errMsg.includes("insufficient") || json.error.code === 403) {
         finalMsg += "¿El proyecto de Apps Script está vinculado a GCP? Revise que la API 'iam.googleapis.com' esté habilitada en el proyecto de Apps Script, o que el script esté enlazado al proyecto GCP estándar.";
      }
      
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: `ERROR GCP: ${errStatus}`,
        riesgo052: "Medio",
        score052: 2,
        comentario052: finalMsg
      };
    }

    let staleKeysCount = 0;
    let userManagedCount = 0;
    const now = new Date();

    if (json.keys && json.keys.length > 0) {
      json.keys.forEach(key => {
        if (key.keyType === 'USER_MANAGED') {
          userManagedCount++;
          
          if (key.validAfterTime) {
            const creationDate = new Date(key.validAfterTime);
            const diffTime = Math.abs(now - creationDate);
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
            
            if (diffDays > 90) {
              staleKeysCount++;
            }
          }
        }
      });
    }

    let riesgo052, comentario052;

    if (staleKeysCount === 0) {
      riesgo052 = "Bajo";
      comentario052 = "La consulta a la API indica que no existen claves de cuenta de servicio gestionadas por el usuario (USER_MANAGED) con una antigüedad superior a 90 días desde su fecha de creación.";
    } else {
      riesgo052 = "Alto";
      comentario052 = `Existen ${staleKeysCount} clave(s) de cuenta de servicio gestionadas por el usuario cuya antigüedad supera los 90 días, evidenciando la ausencia de una rotación criptográfica reciente.`;
    }

    return {
      name: this.name,
      raw: json,
      valorPrincipal: staleKeysCount,
      comentario052: comentario052,
      riesgo052: riesgo052,
      score052: this.calcularScoreDeRiesgo(riesgo052)
    };
  }
}