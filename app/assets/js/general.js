// Peer-widget
const containerElement = document.querySelector(".user.others");

if (state.hasSelectedFile) {
  const popover = definePopover({
    content: `Do you want to send <strong>"${filename}"</strong> to <strong>"${label}"</strong>?`,
    onConfirm: sendFileTransferEnquiry,
    onCancel: cancelFileTransfer,
    confirmButtonLabel: "Send",
    cancelButtonLabel: "Cancel",
    filename: filename,
  });

  containerElement.prepend(popover);
}

// Assuming you have a reference to the relevant container element: containerElement.appendChild(popover);}
if (state.isAwaitingResponse) {
  const popover = definePopover({
    content: `Waiting for <strong>"${label}"</strong> to accept&hellip;`,
    onCancel: abortFileTransfer,
    cancelButtonLabel: "Cancel",
    filename: filename,
  });

  // Append to the appropriate element:
  containerElement.prepend(popover);
}

if (state.hasDeclinedFileTransfer) {
  const popover = definePopover({
    content: `<strong>"${label}"</strong> has declined your request.`,
    onConfirm: cancelFileTransfer,  // Close the popover on confirmation
    confirmButtonLabel: "Ok",
    filename: filename,
  });

  containerElement.prepend(popover);
}

if (state.hasError) {
  const popover = definePopover({
    content: errorTemplateName, // Assuming errorTemplateName contains error message
    onConfirm: cancelFileTransfer,  // Close the popover on confirmation
    confirmButtonLabel: "Ok",
    filename: filename,
  });

  containerElement.prepend(popover);
}

// Recipient related popups
if (state.hasReceivedFileInfo) {
  const popover = definePopover({
    content: `<strong>"${label}"</strong> wants to send you <strong>"${filename}"</strong>.`,
    onConfirm: acceptFileTransfer,
    onCancel: rejectFileTransfer,
    confirmButtonLabel: "Save",
    cancelButtonLabel: "Decline",
    filename: filename,
  });

  containerElement.prepend(popover);
}
