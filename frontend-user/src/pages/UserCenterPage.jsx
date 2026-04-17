import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Mail,
  Shield,
  Smartphone,
  KeyRound,
  CheckCircle,
  XCircle,
  RefreshCw,
  Eye,
  EyeOff,
  Lock,
  AlertCircle,
  User,
  Settings,
  Globe,
  Moon,
  Bell,
  DollarSign,
  Languages,
  Sun,
  Monitor,
  Volume2,
  Vibrate,
  Camera,
  X,
  Save,
  Upload,
  Crop,
  Image as ImageIcon,
  Users
} from "lucide-react";
import { userApi, getApiErrorMessage } from "../services/api";
import { getFullImageUrl } from "../utils/image";
import { useNotification } from "../hooks/useNotification";

function getToken() {
  return localStorage.getItem("userToken") || 
         localStorage.getItem("token") || 
         localStorage.getItem("accessToken") || 
         "";
}

function StatusBadge({ verified, label }) {
  return (
    <div className={`flex items-center gap-2 rounded-full px-3 py-1 text-sm ${
      verified 
        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" 
        : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
    }`}>
      {verified ? <CheckCircle size={14} /> : <XCircle size={14} />}
      <span>{label}</span>
    </div>
  );
}

function getKycText(status) {
  return String(status || "not_submitted").replaceAll("_", " ");
}

function getKycClass(status) {
  const value = String(status || "").toLowerCase();
  if (value === "approved") {
    return "border border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
  if (value === "pending") {
    return "border border-amber-500/30 bg-amber-500/10 text-amber-300";
  }
  if (value === "rejected") {
    return "border border-red-500/30 bg-red-500/10 text-red-300";
  }
  return "border border-white/10 bg-white/[0.04] text-slate-300";
}

// Simple image cropper component
function ImageCropper({ imageFile, onCropComplete, onCancel }) {
  const [zoom, setZoom] = useState(1);
  const [imageSrc, setImageSrc] = useState(null);
  const [imageDimensions, setImageDimensions] = useState({ width: 0, height: 0 });
  const [cropPosition, setCropPosition] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [imageLoaded, setImageLoaded] = useState(false);
  const imageRef = useRef(null);
  const containerRef = useRef(null);
  const cropSize = 200;

  useEffect(() => {
    if (imageFile) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setImageSrc(e.target.result);
      };
      reader.readAsDataURL(imageFile);
    }
  }, [imageFile]);

  useEffect(() => {
    if (imageRef.current && imageLoaded) {
      const img = imageRef.current;
      setImageDimensions({
        width: img.naturalWidth,
        height: img.naturalHeight
      });
      setCropPosition({
        x: (img.naturalWidth - cropSize) / 2,
        y: (img.naturalHeight - cropSize) / 2
      });
    }
  }, [imageLoaded, cropSize]);

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX, y: e.clientY });
  };

  const handleMouseMove = (e) => {
    if (!isDragging || !imageRef.current) return;
    
    const dx = e.clientX - dragStart.x;
    const dy = e.clientY - dragStart.y;
    
    const newX = Math.min(
      Math.max(0, cropPosition.x - dx * (imageDimensions.width / (imageRef.current.clientWidth || 1))),
      imageDimensions.width - cropSize
    );
    const newY = Math.min(
      Math.max(0, cropPosition.y - dy * (imageDimensions.height / (imageRef.current.clientHeight || 1))),
      imageDimensions.height - cropSize
    );
    
    setCropPosition({ x: newX, y: newY });
    setDragStart({ x: e.clientX, y: e.clientY });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const containerStyle = {
    position: 'relative',
    width: '100%',
    height: '300px',
    overflow: 'hidden',
    cursor: isDragging ? 'grabbing' : 'grab',
    backgroundColor: '#1a1a1a',
    borderRadius: '12px',
  };

  const imageStyle = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: `translate(-50%, -50%) scale(${zoom})`,
    maxWidth: 'none',
    maxHeight: 'none',
  };

  const handleCrop = () => {
    if (!imageLoaded || !imageRef.current) {
      alert("Image not ready. Please wait.");
      return;
    }
    const image = imageRef.current;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    canvas.width = cropSize;
    canvas.height = cropSize;
    
    const sx = cropPosition.x;
    const sy = cropPosition.y;
    const sWidth = cropSize;
    const sHeight = cropSize;
    
    ctx.drawImage(
      image,
      sx, sy, sWidth, sHeight,
      0, 0, cropSize, cropSize
    );
    
    canvas.toBlob((blob) => {
      const file = new File([blob], "cropped-avatar.jpg", { type: "image/jpeg" });
      onCropComplete(file);
    }, "image/jpeg", 0.9);
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/90 p-4">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6">
        <h3 className="mb-4 text-xl font-bold text-white">Crop Avatar</h3>
        
        <div className="relative">
          <div 
            ref={containerRef}
            style={containerStyle}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          >
            {imageSrc && (
              <img
                ref={imageRef}
                src={imageSrc}
                alt="Crop preview"
                style={imageStyle}
                draggable={false}
                onLoad={() => setImageLoaded(true)}
              />
            )}
          </div>
          <div className="absolute inset-0 pointer-events-none">
            <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[200px] h-[200px] border-2 border-white shadow-[0_0_0_9999px_rgba(0,0,0,0.5)] rounded-xl" />
          </div>
        </div>
        
        <div className="mt-4">
          <label className="mb-2 block text-sm text-slate-400">Zoom</label>
          <input
            type="range"
            min="1"
            max="3"
            step="0.01"
            value={zoom}
            onChange={(e) => setZoom(parseFloat(e.target.value))}
            className="w-full"
          />
          <p className="mt-2 text-xs text-slate-500">Click and drag the image to position, use zoom to adjust size</p>
        </div>
        
        <div className="mt-6 flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 rounded-xl border border-white/10 bg-white/5 py-2 text-white transition hover:bg-white/10"
          >
            Cancel
          </button>
          <button
            onClick={handleCrop}
            disabled={!imageLoaded}
            className="flex-1 rounded-xl bg-cyan-500 py-2 font-semibold text-black transition hover:bg-cyan-400 disabled:opacity-50"
          >
            Apply Crop
          </button>
        </div>
      </div>
    </div>
  );
}

export default function UserCenterPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const token = getToken();
  const { showSuccess, showError, showVoucher } = useNotification();

  // Tab state
  const [activeTab, setActiveTab] = useState("profile");

  // Loading states
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  
  // User profile data
  const [profile, setProfile] = useState({
    name: "",
    email: "",
    uid: "",
    status: "active",
    kyc_status: "not_submitted",
    country: "Not set",
    avatar_url: "",
    trading_fee_tier: "Regular user",
    email_verified: false,
  });

  // Edit profile states
  const [isEditing, setIsEditing] = useState(false);
  const [profileSaving, setProfileSaving] = useState(false);
  const [editForm, setEditForm] = useState({
    name: "",
    avatarFile: null,
    avatarPreview: "",
  });
  const [showCropper, setShowCropper] = useState(false);
  const [tempAvatarFile, setTempAvatarFile] = useState(null);
  const fileInputRef = useRef(null);
  const cameraInputRef = useRef(null);
  
  // Security states
  const [securityStatus, setSecurityStatus] = useState({
    hasPasscode: false,
    twofaEnabled: false,
  });
  
  // Passcode states
  const [passcodeModalOpen, setPasscodeModalOpen] = useState(false);
  const [passcode, setPasscode] = useState("");
  const [confirmPasscode, setConfirmPasscode] = useState("");
  const [showPasscode, setShowPasscode] = useState(false);
  const [passcodeError, setPasscodeError] = useState("");
  const [savingPasscode, setSavingPasscode] = useState(false);
  
  // Email verification states
  const [verifyModalOpen, setVerifyModalOpen] = useState(false);
  const [verificationCode, setVerificationCode] = useState("");
  const [sendingCode, setSendingCode] = useState(false);
  const [verifyingCode, setVerifyingCode] = useState(false);
  const [verificationError, setVerificationError] = useState("");
  const [verificationSuccess, setVerificationSuccess] = useState("");
  const [countdown, setCountdown] = useState(0);
  
  // Verify passcode modal
  const [verifyPasscodeModalOpen, setVerifyPasscodeModalOpen] = useState(false);
  const [verifyPasscode, setVerifyPasscode] = useState("");
  const [verifyPasscodeError, setVerifyPasscodeError] = useState("");
  const [verifyingPasscode, setVerifyingPasscode] = useState(false);

  // Preferences states
  const [preferences, setPreferences] = useState({
    language: "English",
    currency: "USD",
    appearance: "system",
    notifications: true,
    hapticFeedback: true,
    soundEffects: true,
    chartTimezone: "UTC",
  });

  // Joint Account states
  const [jointModalOpen, setJointModalOpen] = useState(false);
  const [jointAccountStatus, setJointAccountStatus] = useState(null);
  const [jointPartner, setJointPartner] = useState(null);
  const [jointForm, setJointForm] = useState({
    partnerEmail: "",
    partnerKycNumber: "",
  });
  const [submittingJoint, setSubmittingJoint] = useState(false);

  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  // Load all data
  useEffect(() => {
    loadAllData();
  }, []);

  // Load joint account status
  useEffect(() => {
    if (token) {
      loadJointAccountStatus();
    }
  }, [token]);

  // Countdown timer
  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [countdown]);

  // Cleanup avatar preview
  useEffect(() => {
    return () => {
      if (editForm.avatarPreview?.startsWith("blob:")) {
        URL.revokeObjectURL(editForm.avatarPreview);
      }
    };
  }, [editForm.avatarPreview]);

  async function loadAllData() {
    try {
      setLoading(true);
      setError("");
      
      const profileRes = await userApi.getProfile(token);
      if (profileRes?.data?.success) {
        const userData = profileRes.data.data;
        setProfile({
          name: userData.name || "",
          email: userData.email || "",
          uid: userData.uid || "",
          status: userData.status || "active",
          kyc_status: userData.kyc_status || "not_submitted",
          country: userData.country || "Not set",
          avatar_url: userData.avatar_url || "",
          trading_fee_tier: userData.trading_fee_tier || "Regular user",
          email_verified: userData.email_verified === 1,
        });
      }
      
      const securityRes = await userApi.securityStatus(token);
      if (securityRes?.data?.success) {
        setSecurityStatus({
          hasPasscode: securityRes.data.data?.hasPasscode || false,
          twofaEnabled: securityRes.data.data?.twofaEnabled || false,
        });
      }
      
      const savedPrefs = localStorage.getItem("user_preferences");
      if (savedPrefs) {
        try {
          setPreferences(JSON.parse(savedPrefs));
        } catch (e) {}
      }
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  async function loadJointAccountStatus() {
    try {
      const res = await userApi.getJointAccountStatus(token);
      if (res?.data?.success) {
        const data = res.data.data;
        setJointAccountStatus(data);
        
        // If has active joint account, fetch partner info
        if (data.hasJointAccount && data.jointAccount) {
          const currentUid = profile.uid;
          const partnerUid = data.jointAccount.user1_uid === currentUid 
            ? data.jointAccount.user2_uid 
            : data.jointAccount.user1_uid;
          
          if (partnerUid) {
            try {
              const partnerRes = await fetch(`${import.meta.env.VITE_API_BASE_URL || "https://cryptopulse-4rhe.onrender.com"}/api/user/by-uid/${partnerUid}`, {
                headers: { Authorization: `Bearer ${token}` }
              });
              const partnerData = await partnerRes.json();
              if (partnerData.success) {
                setJointPartner(partnerData.data);
              }
            } catch (err) {
              console.error("Failed to load partner info:", err);
            }
          }
        } else {
          setJointPartner(null);
        }
      }
    } catch (err) {
      console.error("Failed to load joint account status:", err);
    }
  }

  async function forceRefreshUserData() {
    try {
      setRefreshing(true);
      localStorage.removeItem("user");
      localStorage.removeItem("userData");
      await loadAllData();
      await loadJointAccountStatus();
      showSuccess("User data refreshed successfully!");
    } catch (err) {
      showError(getApiErrorMessage(err));
    } finally {
      setRefreshing(false);
    }
  }

  // Profile functions
  function openEditProfile() {
    setEditForm({
      name: profile.name,
      avatarFile: null,
      avatarPreview: profile.avatar_url,
    });
    setIsEditing(true);
    setError("");
    setMessage("");
  }

  function closeEditProfile() {
    if (editForm.avatarPreview?.startsWith("blob:")) {
      URL.revokeObjectURL(editForm.avatarPreview);
    }
    setIsEditing(false);
    setShowCropper(false);
    setTempAvatarFile(null);
  }

  function handleEditProfileChange(e) {
    setEditForm(prev => ({ ...prev, name: e.target.value }));
  }

  function handleAvatarFileSelect(file) {
    if (file) {
      setTempAvatarFile(file);
      setShowCropper(true);
    }
  }

  function handleCropComplete(croppedFile) {
    const previewUrl = URL.createObjectURL(croppedFile);
    setEditForm(prev => ({
      ...prev,
      avatarFile: croppedFile,
      avatarPreview: previewUrl,
    }));
    setShowCropper(false);
    setTempAvatarFile(null);
  }

  function handleCameraCapture(e) {
    const file = e.target.files?.[0];
    if (file) {
      handleAvatarFileSelect(file);
    }
  }

  async function handleSaveProfile() {
    try {
      setProfileSaving(true);
      setError("");
      setMessage("");

      const name = editForm.name.trim();
      if (!name) {
        showError("Name is required");
        return;
      }

      let avatarUrl = profile.avatar_url;
      if (editForm.avatarFile) {
        const uploadRes = await userApi.uploadProfilePicture(editForm.avatarFile, token);
        avatarUrl = uploadRes?.data?.data?.avatar_url || avatarUrl;
      }

      await userApi.updateProfile({ name }, token);
      
      setProfile(prev => ({ ...prev, name, avatar_url: avatarUrl }));
      showSuccess("Profile updated successfully!");
      setIsEditing(false);
      
      const updatedUser = { ...profile, name, avatar_url: avatarUrl };
      localStorage.setItem("user", JSON.stringify(updatedUser));
      localStorage.setItem("userData", JSON.stringify(updatedUser));
    } catch (err) {
      showError(getApiErrorMessage(err));
    } finally {
      setProfileSaving(false);
    }
  }

  // Security functions
  async function handleSetPasscode() {
    if (!passcode || passcode.length < 4) {
      setPasscodeError("Passcode must be at least 4 digits");
      return;
    }
    if (passcode !== confirmPasscode) {
      setPasscodeError("Passcodes do not match");
      return;
    }
    
    try {
      setSavingPasscode(true);
      await userApi.setPasscode({ passcode }, token);
      setSecurityStatus(prev => ({ ...prev, hasPasscode: true }));
      setPasscodeModalOpen(false);
      setPasscode("");
      setConfirmPasscode("");
      showSuccess("Passcode set successfully!");
    } catch (err) {
      setPasscodeError(getApiErrorMessage(err));
    } finally {
      setSavingPasscode(false);
    }
  }

  async function handleSendVerificationCode() {
    if (countdown > 0) {
      showError(`Please wait ${countdown} seconds`);
      return;
    }
    
    try {
      setSendingCode(true);
      const response = await userApi.sendEmailVerificationCode(token);
      if (response?.data?.success) {
        if (response.data.code) {
          showSuccess(`Your verification code is: ${response.data.code}`);
        } else {
          showSuccess("Verification code sent!");
        }
        setCountdown(60);
      } else {
        showError(response?.data?.message || "Failed to send code");
      }
    } catch (err) {
      showError(getApiErrorMessage(err));
    } finally {
      setSendingCode(false);
    }
  }

  async function handleVerifyCode() {
    if (!verificationCode || verificationCode.length !== 6) {
      showError("Enter valid 6-digit code");
      return;
    }
    
    try {
      setVerifyingCode(true);
      const response = await userApi.verifyEmailCode({ code: verificationCode }, token);
      if (response?.data?.success) {
        showSuccess("Email verified!");
        setProfile(prev => ({ ...prev, email_verified: true }));
        setTimeout(() => {
          setVerifyModalOpen(false);
          setVerificationCode("");
          forceRefreshUserData();
        }, 2000);
      } else {
        showError(response?.data?.message || "Invalid code");
      }
    } catch (err) {
      showError(getApiErrorMessage(err));
    } finally {
      setVerifyingCode(false);
    }
  }

  async function handleVerifyPasscode() {
    if (!verifyPasscode) {
      setVerifyPasscodeError("Enter your passcode");
      return;
    }
    
    try {
      setVerifyingPasscode(true);
      const response = await userApi.verifyPasscode({ passcode: verifyPasscode }, token);
      if (response?.data?.success) {
        setVerifyPasscodeModalOpen(false);
        setVerifyPasscode("");
        showSuccess("Passcode verified!");
      } else {
        setVerifyPasscodeError(response?.data?.message || "Invalid passcode");
      }
    } catch (err) {
      setVerifyPasscodeError(getApiErrorMessage(err));
    } finally {
      setVerifyingPasscode(false);
    }
  }

  // Joint Account functions
  async function handleRequestJointAccount() {
    if (!jointForm.partnerEmail.trim()) {
      showError("Partner email is required");
      return;
    }
    
    try {
      setSubmittingJoint(true);
      setError("");
      
      const res = await userApi.requestJointAccount({
        partnerEmail: jointForm.partnerEmail.trim(),
        partnerKycNumber: jointForm.partnerKycNumber.trim(),
      }, token);
      
      if (res?.data?.success) {
        showSuccess(res.data.message);
        
        showVoucher({
          title: "Joint Account Requested",
          type: "joint_account",
          transactionId: res.data.data?.requestId,
          data: {
            requestId: res.data.data?.requestId,
            partnerEmail: jointForm.partnerEmail.trim(),
            partnerUid: "",
            created_at: new Date().toISOString(),
          },
        });
        
        setJointModalOpen(false);
        setJointForm({ partnerEmail: "", partnerKycNumber: "" });
        await loadJointAccountStatus();
      } else {
        showError(res?.data?.message || "Failed to send request");
      }
    } catch (err) {
      showError(getApiErrorMessage(err));
    } finally {
      setSubmittingJoint(false);
    }
  }

  // Preferences functions
  function updatePreference(key, value) {
    const newPrefs = { ...preferences, [key]: value };
    setPreferences(newPrefs);
    localStorage.setItem("user_preferences", JSON.stringify(newPrefs));
    showSuccess(`${key} updated successfully`);
  }

  const avatarUrl = useMemo(() => getFullImageUrl(profile.avatar_url), [profile.avatar_url]);
  const editAvatarSrc = useMemo(() => getFullImageUrl(editForm.avatarPreview), [editForm.avatarPreview]);

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6 px-4 py-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">User Center</h1>
        <p className="mt-1 text-sm text-slate-400">Profile, security, and preference settings</p>
      </div>

      {/* Refresh Button */}
      <div className="rounded-2xl border border-amber-500/20 bg-amber-500/10 p-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="font-semibold text-amber-300">Need to refresh your account?</h3>
            <p className="text-sm text-amber-200/70">
              Click refresh to update your account status from server.
            </p>
          </div>
          <button
            onClick={forceRefreshUserData}
            disabled={refreshing}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-amber-500 px-4 py-2 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:opacity-50"
          >
            <RefreshCw size={16} className={refreshing ? "animate-spin" : ""} />
            {refreshing ? "Refreshing..." : "Refresh Account"}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-white/10">
        <button
          onClick={() => setActiveTab("profile")}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition ${
            activeTab === "profile"
              ? "border-b-2 border-cyan-500 text-cyan-400"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <User size={16} />
          Profile
        </button>
        <button
          onClick={() => setActiveTab("security")}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition ${
            activeTab === "security"
              ? "border-b-2 border-cyan-500 text-cyan-400"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <Shield size={16} />
          Security
        </button>
        <button
          onClick={() => setActiveTab("preferences")}
          className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition ${
            activeTab === "preferences"
              ? "border-b-2 border-cyan-500 text-cyan-400"
              : "text-slate-400 hover:text-white"
          }`}
        >
          <Settings size={16} />
          Preferences
        </button>
      </div>

      {/* ==================== PROFILE TAB ==================== */}
      {activeTab === "profile" && (
        <div className="space-y-5">
          {/* Profile Header Card */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex flex-col items-center gap-4 text-center sm:flex-row sm:text-left">
              <div className="h-20 w-20 overflow-hidden rounded-full border border-white/10 bg-white/[0.03]">
                {avatarUrl ? (
                  <img src={avatarUrl} alt="avatar" className="h-full w-full object-cover" />
                ) : (
                  <span className="flex h-full w-full items-center justify-center text-2xl text-white">
                    {profile.email?.[0]?.toUpperCase() || "U"}
                  </span>
                )}
              </div>
              <div className="flex-1">
                <h2 className="text-xl font-bold text-white">{profile.name || "User"}</h2>
                <p className="text-sm text-slate-400">{profile.email}</p>
                <div className="mt-2 flex flex-wrap justify-center gap-2 sm:justify-start">
                  <span className={`rounded-full px-3 py-1 text-xs ${getKycClass(profile.kyc_status)}`}>
                    KYC: {getKycText(profile.kyc_status)}
                  </span>
                  <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1 text-xs text-slate-300">
                    {profile.trading_fee_tier || "Regular user"}
                  </span>
                </div>
              </div>
              <button
                onClick={openEditProfile}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white transition hover:bg-white/10"
              >
                Edit profile
              </button>
            </div>
          </div>

          {/* Account Information Card */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <h3 className="mb-4 font-semibold text-white">Account information</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-slate-400">UID</span>
                <span className="text-white">{profile.uid || "--"}</span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-slate-400">Email verification</span>
                <StatusBadge verified={profile.email_verified} label={profile.email_verified ? "Verified" : "Not verified"} />
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-slate-400">Identity verification</span>
                <span className={`rounded-full px-3 py-1 text-xs ${getKycClass(profile.kyc_status)}`}>
                  {getKycText(profile.kyc_status)}
                </span>
              </div>
              <div className="flex justify-between border-b border-white/5 pb-2">
                <span className="text-slate-400">Country/Region</span>
                <span className="text-white">{profile.country}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Trading fee tier</span>
                <span className="text-white">{profile.trading_fee_tier}</span>
              </div>
            </div>
          </div>

          {/* Edit Profile Modal */}
          {isEditing && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm">
              <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-5">
                <div className="mb-5 flex items-center justify-between">
                  <h3 className="text-xl font-bold text-white">Edit profile</h3>
                  <button onClick={closeEditProfile} className="text-slate-400 hover:text-white">
                    <X size={20} />
                  </button>
                </div>
                <div className="space-y-5">
                  {/* Avatar Section */}
                  <div className="flex flex-col items-center">
                    <div className="relative h-24 w-24 overflow-hidden rounded-full bg-white/5 ring-1 ring-white/10">
                      {editAvatarSrc ? (
                        <img src={editAvatarSrc} alt="Preview" className="h-full w-full object-cover" />
                      ) : (
                        <User size={36} className="m-auto mt-6 text-slate-400" />
                      )}
                    </div>
                    
                    <div className="mt-3 flex gap-2">
                      <label className="cursor-pointer rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white transition hover:bg-white/10">
                        <Upload size={14} className="mr-1 inline" />
                        Gallery
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept="image/*"
                          className="hidden"
                          onChange={(e) => {
                            const file = e.target.files?.[0];
                            if (file) handleAvatarFileSelect(file);
                          }}
                        />
                      </label>
                      
                      <label className="cursor-pointer rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white transition hover:bg-white/10">
                        <Camera size={14} className="mr-1 inline" />
                        Camera
                        <input
                          ref={cameraInputRef}
                          type="file"
                          accept="image/*"
                          capture="environment"
                          className="hidden"
                          onChange={handleCameraCapture}
                        />
                      </label>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">Click Gallery or Camera to upload</p>
                  </div>

                  {/* Name Input */}
                  <div>
                    <label className="mb-2 block text-sm text-slate-400">Profile name</label>
                    <input
                      type="text"
                      value={editForm.name}
                      onChange={handleEditProfileChange}
                      placeholder="Enter your name"
                      className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white outline-none focus:border-cyan-500"
                    />
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-3">
                    <button 
                      onClick={handleSaveProfile} 
                      disabled={profileSaving} 
                      className="flex-1 rounded-xl bg-cyan-500 py-2 font-semibold text-black transition hover:bg-cyan-400 disabled:opacity-50"
                    >
                      <Save size={14} className="mr-1 inline" />
                      {profileSaving ? "Saving..." : "Save Changes"}
                    </button>
                    <button 
                      onClick={closeEditProfile} 
                      className="flex-1 rounded-xl border border-white/10 py-2 text-white transition hover:bg-white/5"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Image Cropper Modal */}
          {showCropper && tempAvatarFile && (
            <ImageCropper
              imageFile={tempAvatarFile}
              onCropComplete={handleCropComplete}
              onCancel={() => {
                setShowCropper(false);
                setTempAvatarFile(null);
              }}
            />
          )}
        </div>
      )}

      {/* ==================== SECURITY TAB ==================== */}
      {activeTab === "security" && (
        <div className="space-y-5">
          {/* Email Verification */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3">
                <div className="rounded-full bg-cyan-500/10 p-2">
                  <Mail className="h-5 w-5 text-cyan-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Email Verification</h3>
                  <p className="text-sm text-slate-400">{profile.email}</p>
                  <div className="mt-2">
                    <StatusBadge verified={profile.email_verified} label={profile.email_verified ? "Verified" : "Not Verified"} />
                  </div>
                </div>
              </div>
              {!profile.email_verified && (
                <button onClick={() => setVerifyModalOpen(true)} className="rounded-xl bg-cyan-500 px-4 py-2 text-sm font-semibold text-black">
                  Verify Email
                </button>
              )}
            </div>
          </div>

          {/* Transaction Passcode */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3">
                <div className="rounded-full bg-purple-500/10 p-2">
                  <Lock className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Transaction Passcode</h3>
                  <p className="text-sm text-slate-400">
                    {securityStatus.hasPasscode ? "Passcode is set. Used for sensitive operations." : "No passcode set. Set one to secure your account."}
                  </p>
                  <div className="mt-2">
                    <StatusBadge verified={securityStatus.hasPasscode} label={securityStatus.hasPasscode ? "Enabled" : "Not Set"} />
                  </div>
                </div>
              </div>
              <button onClick={() => setPasscodeModalOpen(true)} className={`rounded-xl px-4 py-2 text-sm font-semibold ${securityStatus.hasPasscode ? "border border-white/10 bg-white/5 text-white" : "bg-purple-500 text-black"}`}>
                <KeyRound size={14} className="mr-1 inline" />
                {securityStatus.hasPasscode ? "Change Passcode" : "Set Passcode"}
              </button>
            </div>
          </div>

          {/* 2FA Section */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3">
                <div className="rounded-full bg-emerald-500/10 p-2">
                  <Smartphone className="h-5 w-5 text-emerald-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Two-Factor Authentication</h3>
                  <p className="text-sm text-slate-400">
                    {securityStatus.twofaEnabled ? "2FA is enabled. Your account is more secure." : "Enhance security with 2FA protection."}
                  </p>
                  <div className="mt-2">
                    <StatusBadge verified={securityStatus.twofaEnabled} label={securityStatus.twofaEnabled ? "Enabled" : "Disabled"} />
                  </div>
                </div>
              </div>
              <button onClick={() => securityStatus.hasPasscode ? setVerifyPasscodeModalOpen(true) : setPasscodeModalOpen(true)} className={`rounded-xl px-4 py-2 text-sm font-semibold ${securityStatus.twofaEnabled ? "border border-white/10 bg-white/5 text-white" : "bg-emerald-500 text-black"}`}>
                <Shield size={14} className="mr-1 inline" />
                {securityStatus.twofaEnabled ? "Disable 2FA" : "Enable 2FA"}
              </button>
            </div>
          </div>

          {/* Joint Account Section - FIXED */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 flex-1 items-start gap-3">
                <div className="shrink-0 rounded-full bg-indigo-500/10 p-2">
                  <Users className="h-5 w-5 text-indigo-400" />
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="font-semibold text-white">Joint Account</h3>
                  <p className="text-sm text-slate-400 break-words">
                    Connect with another user to share balances and manage assets together
                  </p>
                  {jointAccountStatus?.hasJointAccount && (
                    <div className="mt-2">
                      <StatusBadge verified={true} label="Active Joint Account" />
                      <p className="mt-1 text-xs text-slate-500 break-all">
                        Account ID: {jointAccountStatus.jointAccount?.account_id}
                      </p>
                      {jointPartner && (
                        <p className="mt-1 text-xs text-indigo-300 break-words">
                          Connected with: {jointPartner.name || jointPartner.email}
                        </p>
                      )}
                    </div>
                  )}
                  {jointAccountStatus?.pendingRequest && (
                    <div className="mt-2">
                      <StatusBadge verified={false} label="Request Pending Approval" />
                      <p className="mt-1 text-xs text-amber-300">
                        Awaiting admin approval for your joint account request
                      </p>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="shrink-0">
                {!jointAccountStatus?.hasJointAccount && !jointAccountStatus?.pendingRequest ? (
                  <button
                    onClick={() => setJointModalOpen(true)}
                    className="whitespace-nowrap rounded-xl bg-indigo-500 px-4 py-2 text-sm font-semibold text-black hover:bg-indigo-400 transition"
                  >
                    Request Joint Account
                  </button>
                ) : jointAccountStatus?.pendingRequest ? (
                  <span className="inline-block whitespace-nowrap rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-2 text-sm text-amber-300">
                    Awaiting Admin Approval
                  </span>
                ) : (
                  <span className="inline-block whitespace-nowrap rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-300">
                    Joint Account Active
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================== PREFERENCES TAB ==================== */}
      {activeTab === "preferences" && (
        <div className="space-y-4">
          {/* Language */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Languages className="h-5 w-5 text-cyan-400" />
                <div>
                  <h3 className="font-semibold text-white">Language</h3>
                  <p className="text-xs text-slate-400">Choose your preferred language</p>
                </div>
              </div>
              <select
                value={preferences.language}
                onChange={(e) => updatePreference("language", e.target.value)}
                className="rounded-xl border border-white/10 bg-slate-800 px-3 py-2 text-white"
              >
                <option>English</option>
                <option>Spanish</option>
                <option>French</option>
                <option>German</option>
                <option>Chinese</option>
                <option>Japanese</option>
              </select>
            </div>
          </div>

          {/* Currency */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <DollarSign className="h-5 w-5 text-emerald-400" />
                <div>
                  <h3 className="font-semibold text-white">Currency</h3>
                  <p className="text-xs text-slate-400">Display currency for assets</p>
                </div>
              </div>
              <select
                value={preferences.currency}
                onChange={(e) => updatePreference("currency", e.target.value)}
                className="rounded-xl border border-white/10 bg-slate-800 px-3 py-2 text-white"
              >
                <option>USD</option>
                <option>EUR</option>
                <option>GBP</option>
                <option>JPY</option>
                <option>CNY</option>
              </select>
            </div>
          </div>

          {/* Appearance */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {preferences.appearance === "light" ? <Sun className="h-5 w-5 text-yellow-400" /> : preferences.appearance === "dark" ? <Moon className="h-5 w-5 text-slate-400" /> : <Monitor className="h-5 w-5 text-blue-400" />}
                <div>
                  <h3 className="font-semibold text-white">Appearance</h3>
                  <p className="text-xs text-slate-400">Light, Dark, or System default</p>
                </div>
              </div>
              <select
                value={preferences.appearance}
                onChange={(e) => updatePreference("appearance", e.target.value)}
                className="rounded-xl border border-white/10 bg-slate-800 px-3 py-2 text-white"
              >
                <option value="light">Light</option>
                <option value="dark">Dark</option>
                <option value="system">System</option>
              </select>
            </div>
          </div>

          {/* Notifications */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Bell className="h-5 w-5 text-amber-400" />
                <div>
                  <h3 className="font-semibold text-white">Notifications</h3>
                  <p className="text-xs text-slate-400">Push notifications and alerts</p>
                </div>
              </div>
              <button
                onClick={() => updatePreference("notifications", !preferences.notifications)}
                className={`h-6 w-11 rounded-full transition ${preferences.notifications ? "bg-cyan-500" : "bg-slate-700"}`}
              >
                <div className={`h-5 w-5 rounded-full bg-white transition ${preferences.notifications ? "ml-5" : "ml-0.5"} mt-0.5`} />
              </button>
            </div>
          </div>

          {/* Haptic Feedback */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Vibrate className="h-5 w-5 text-purple-400" />
                <div>
                  <h3 className="font-semibold text-white">Haptic feedback</h3>
                  <p className="text-xs text-slate-400">Vibration on actions</p>
                </div>
              </div>
              <button
                onClick={() => updatePreference("hapticFeedback", !preferences.hapticFeedback)}
                className={`h-6 w-11 rounded-full transition ${preferences.hapticFeedback ? "bg-cyan-500" : "bg-slate-700"}`}
              >
                <div className={`h-5 w-5 rounded-full bg-white transition ${preferences.hapticFeedback ? "ml-5" : "ml-0.5"} mt-0.5`} />
              </button>
            </div>
          </div>

          {/* Sound Effects */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Volume2 className="h-5 w-5 text-blue-400" />
                <div>
                  <h3 className="font-semibold text-white">Sound effects</h3>
                  <p className="text-xs text-slate-400">Play sounds on actions</p>
                </div>
              </div>
              <button
                onClick={() => updatePreference("soundEffects", !preferences.soundEffects)}
                className={`h-6 w-11 rounded-full transition ${preferences.soundEffects ? "bg-cyan-500" : "bg-slate-700"}`}
              >
                <div className={`h-5 w-5 rounded-full bg-white transition ${preferences.soundEffects ? "ml-5" : "ml-0.5"} mt-0.5`} />
              </button>
            </div>
          </div>

          {/* Chart Timezone */}
          <div className="rounded-2xl border border-white/10 bg-slate-900/50 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Globe className="h-5 w-5 text-indigo-400" />
                <div>
                  <h3 className="font-semibold text-white">Chart timezone</h3>
                  <p className="text-xs text-slate-400">24h change & chart timezone</p>
                </div>
              </div>
              <select
                value={preferences.chartTimezone}
                onChange={(e) => updatePreference("chartTimezone", e.target.value)}
                className="rounded-xl border border-white/10 bg-slate-800 px-3 py-2 text-white"
              >
                <option>UTC</option>
                <option>EST</option>
                <option>CST</option>
                <option>PST</option>
                <option>GMT</option>
                <option>Local</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* ==================== MODALS ==================== */}

      {/* Set Passcode Modal */}
      {passcodeModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6">
            <h2 className="mb-4 text-xl font-bold text-white">{securityStatus.hasPasscode ? "Change Passcode" : "Set Passcode"}</h2>
            <div className="space-y-4">
              <div>
                <label className="mb-2 block text-sm text-slate-400">Enter Passcode (min 4 digits)</label>
                <div className="relative">
                  <input
                    type={showPasscode ? "text" : "password"}
                    value={passcode}
                    onChange={(e) => setPasscode(e.target.value)}
                    placeholder="Enter 4-6 digit passcode"
                    className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white outline-none focus:border-purple-500"
                    maxLength={6}
                  />
                  <button onClick={() => setShowPasscode(!showPasscode)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400">
                    {showPasscode ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </div>
              <div>
                <label className="mb-2 block text-sm text-slate-400">Confirm Passcode</label>
                <input
                  type={showPasscode ? "text" : "password"}
                  value={confirmPasscode}
                  onChange={(e) => setConfirmPasscode(e.target.value)}
                  placeholder="Confirm your passcode"
                  className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white outline-none focus:border-purple-500"
                  maxLength={6}
                />
              </div>
              {passcodeError && <div className="rounded-xl bg-red-500/10 p-3 text-sm text-red-400">{passcodeError}</div>}
            </div>
            <div className="mt-6 flex gap-3">
              <button onClick={() => { setPasscodeModalOpen(false); setPasscode(""); setConfirmPasscode(""); setPasscodeError(""); }} className="flex-1 rounded-xl border border-white/10 bg-white/5 py-2 text-white">
                Cancel
              </button>
              <button onClick={handleSetPasscode} disabled={savingPasscode} className="flex-1 rounded-xl bg-purple-500 py-2 font-semibold text-black">
                {savingPasscode ? "Saving..." : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Email Verification Modal */}
      {verifyModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6">
            <h2 className="mb-2 text-xl font-bold text-white">Verify Email</h2>
            <p className="mb-4 text-sm text-slate-400">Verification code will be sent to {profile.email}</p>
            <button onClick={handleSendVerificationCode} disabled={sendingCode || countdown > 0} className="w-full rounded-xl bg-cyan-500 py-3 font-semibold text-black disabled:opacity-50">
              {sendingCode ? <RefreshCw size={18} className="mx-auto animate-spin" /> : countdown > 0 ? `Resend in ${countdown}s` : "Send Verification Code"}
            </button>
            <div className="mt-4">
              <label className="mb-2 block text-sm text-slate-400">Enter 6-digit code</label>
              <input type="text" value={verificationCode} onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, "").slice(0, 6))} placeholder="000000" className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-center text-2xl tracking-widest text-white outline-none focus:border-cyan-500" maxLength={6} />
            </div>
            <div className="mt-6 flex gap-3">
              <button onClick={() => { setVerifyModalOpen(false); setVerificationCode(""); setVerificationError(""); setVerificationSuccess(""); }} className="flex-1 rounded-xl border border-white/10 bg-white/5 py-2 text-white">
                Cancel
              </button>
              <button onClick={handleVerifyCode} disabled={verifyingCode || !verificationCode} className="flex-1 rounded-xl bg-cyan-500 py-2 font-semibold text-black">
                {verifyingCode ? "Verifying..." : "Verify"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Verify Passcode Modal */}
      {verifyPasscodeModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6">
            <h2 className="mb-4 text-xl font-bold text-white">Verify Passcode</h2>
            <p className="mb-4 text-sm text-slate-400">Please enter your passcode to continue</p>
            <input type="password" value={verifyPasscode} onChange={(e) => setVerifyPasscode(e.target.value)} placeholder="Enter your passcode" className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white outline-none focus:border-purple-500" />
            {verifyPasscodeError && <div className="mt-3 rounded-xl bg-red-500/10 p-3 text-sm text-red-400">{verifyPasscodeError}</div>}
            <div className="mt-6 flex gap-3">
              <button onClick={() => { setVerifyPasscodeModalOpen(false); setVerifyPasscode(""); setVerifyPasscodeError(""); }} className="flex-1 rounded-xl border border-white/10 bg-white/5 py-2 text-white">
                Cancel
              </button>
              <button onClick={handleVerifyPasscode} disabled={verifyingPasscode} className="flex-1 rounded-xl bg-purple-500 py-2 font-semibold text-black">
                {verifyingPasscode ? "Verifying..." : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Joint Account Request Modal */}
      {jointModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-6">
            <h2 className="mb-4 text-xl font-bold text-white">Request Joint Account</h2>
            <p className="mb-4 text-sm text-slate-400">
              Enter the email of the user you want to create a joint account with.
              Both users must have completed KYC verification.
            </p>
            
            <div className="space-y-4">
              <div>
                <label className="mb-2 block text-sm text-slate-400">Partner's Email</label>
                <input
                  type="email"
                  value={jointForm.partnerEmail}
                  onChange={(e) => setJointForm(prev => ({ ...prev, partnerEmail: e.target.value }))}
                  placeholder="partner@example.com"
                  className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white outline-none focus:border-indigo-500"
                />
              </div>
              
              <div>
                <label className="mb-2 block text-sm text-slate-400">Partner's KYC Number (Optional)</label>
                <input
                  type="text"
                  value={jointForm.partnerKycNumber}
                  onChange={(e) => setJointForm(prev => ({ ...prev, partnerKycNumber: e.target.value }))}
                  placeholder="Enter KYC number if available"
                  className="w-full rounded-xl border border-white/10 bg-slate-800 px-4 py-3 text-white outline-none focus:border-indigo-500"
                />
              </div>
            </div>
            
            <div className="mt-6 flex gap-3">
              <button
                onClick={() => {
                  setJointModalOpen(false);
                  setJointForm({ partnerEmail: "", partnerKycNumber: "" });
                  setError("");
                }}
                className="flex-1 rounded-xl border border-white/10 bg-white/5 py-2 text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleRequestJointAccount}
                disabled={submittingJoint}
                className="flex-1 rounded-xl bg-indigo-500 py-2 font-semibold text-black disabled:opacity-50"
              >
                {submittingJoint ? "Sending..." : "Send Request"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}